import hashlib
import pefile
import math
import re

SUSPICIOUS_API_KEYWORDS = [
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
    "GetProcAddress", "LoadLibrary", "WinExec", "ShellExecute",
    "InternetOpen", "InternetConnect", "URLDownloadToFile",
    "RegSetValue", "RegCreateKey", "RegDeleteValue",
    "GetAsyncKeyState", "SetWindowsHook", "WSASocket", "connect",
    "CreateProcess", "OpenProcess", "AdjustTokenPrivileges",
]

SYSTEM_DLLS = [
    "kernel32.dll", "user32.dll", "advapi32.dll", "gdi32.dll",
    "shell32.dll", "ntdll.dll", "ws2_32.dll", "ole32.dll",
    "shlwapi.dll", "comdlg32.dll", "secur32.dll",
]

STANDARD_SECTIONS = [
    ".text", ".rdata", ".data", ".rsrc", ".pdata", ".reloc",
]

def compute_hashes(file_path: str) -> dict:
    hashes = {"md5": None, "sha1": None, "sha256": None}
    buf_size = 65536
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(buf_size)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    hashes["md5"] = md5.hexdigest()
    hashes["sha1"] = sha1.hexdigest()
    hashes["sha256"] = sha256.hexdigest()
    return hashes


def load_pe(file_path: str) -> pefile.PE:
    return pefile.PE(file_path)


def get_basic_info(pe: pefile.PE) -> dict:
    return {
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "number_of_sections": pe.FILE_HEADER.NumberOfSections,
        "machine": hex(pe.FILE_HEADER.Machine),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
    }


def section_entropy(section) -> float:
    data = section.get_data()
    if not data:
        return 0.0

    occurrences = [0] * 256
    for b in data:
        occurrences[b] += 1

    entropy = 0.0
    length = len(data)
    for count in occurrences:
        if count == 0:
            continue
        p_x = float(count) / length
        entropy -= p_x * math.log2(p_x)
    return entropy


def get_sections_info(pe: pefile.PE) -> list:
    sections = []
    for section in pe.sections:
        name = section.Name.decode(errors="ignore").strip("\x00")
        sections.append({
            "name": name,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": round(section_entropy(section), 3),
            "characteristics": hex(section.Characteristics),
        })
    return sections


def get_imports(pe: pefile.PE) -> list:
    imports = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode(errors="ignore").lower()
        functions = []
        for imp in entry.imports:
            func_name = imp.name.decode(errors="ignore") if imp.name else f"Ordinal_{imp.ordinal}"
            functions.append(func_name)
        imports.append({"dll": dll_name, "functions": functions})
    return imports


def get_exports(pe: pefile.PE) -> list:
    exports = []
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return exports

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode(errors="ignore") if exp.name else f"Ordinal_{exp.ordinal}"
        exports.append(name)
    return exports


def extract_strings(file_path: str, min_length: int = 4) -> list:
    with open(file_path, "rb") as f:
        data = f.read()

    ascii_re = rb"[ -~]{%d,}" % min_length
    unicode_re = rb"(?:[ -~]\x00){%d,}" % min_length

    strings = re.findall(ascii_re, data)
    ustrings = [s.decode("utf-16le", errors="ignore") for s in re.findall(unicode_re, data)]

    decoded_ascii = [s.decode(errors="ignore") for s in strings]
    return decoded_ascii + ustrings


def get_version_info(pe: pefile.PE) -> dict:
    info = {
        "company_name": None,
        "file_description": None,
        "product_name": None,
    }
    if not hasattr(pe, "FileInfo"):
        return info

    try:
        for fileinfo in pe.FileInfo:
            if fileinfo.Key == b"StringFileInfo":
                for st in fileinfo.StringTable:
                    for k, v in st.entries.items():
                        key = k.decode(errors="ignore")
                        val = v.decode(errors="ignore")
                        if key == "CompanyName":
                            info["company_name"] = val
                        elif key == "FileDescription":
                            info["file_description"] = val
                        elif key == "ProductName":
                            info["product_name"] = val
    except Exception:
        pass

    return info


def get_signature_info(pe: pefile.PE) -> dict:
    signed = False
    size = 0
    try:
        dir_sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        size = dir_sec.Size
        if size > 0:
            signed = True
    except Exception:
        pass

    return {"signed": signed, "raw_size": size}


def compute_suspicious_score(
    sections: list,
    imports: list,
    strings: list,
    version_info: dict,
    sig_info: dict,
    vt_result: dict | None = None,
) -> dict:
    score = 0
    reasons: list[str] = []

    # High entropy (possible packing)
    high_entropy_sections = [s for s in sections if s["entropy"] > 7.2]
    if high_entropy_sections:
        score += 25
        reasons.append(f"High entropy in {len(high_entropy_sections)} section(s) (possible packing)")

    # Suspicious APIs
    suspicious_import_hits = 0
    for entry in imports:
        for func in entry["functions"]:
            for kw in SUSPICIOUS_API_KEYWORDS:
                if kw.lower() in func.lower():
                    suspicious_import_hits += 1
    if suspicious_import_hits > 0:
        score += min(30, suspicious_import_hits * 3)
        reasons.append(f"{suspicious_import_hits} suspicious API imports")

    # Suspicious strings
    suspicious_strings_hits = 0
    url_hits = 0
    reg_hits = 0
    net_hits = 0
    crypto_hits = 0
    inject_hits = 0

    for s in strings:
        lower = s.lower()
        if "http://" in lower or "https://" in lower:
            url_hits += 1
        if "cmd.exe" in lower or "powershell" in lower:
            suspicious_strings_hits += 1
        if "regedit" in lower or "hkey_" in lower:
            reg_hits += 1
        if "socket" in lower or "connect" in lower or "tcp" in lower or "udp" in lower:
            net_hits += 1
        if "aes" in lower or "rsa" in lower or "base64" in lower or "encrypt" in lower:
            crypto_hits += 1
        if "shellcode" in lower or "injection" in lower or "remote thread" in lower:
            inject_hits += 1

    total_susp = suspicious_strings_hits + url_hits + reg_hits + net_hits + crypto_hits + inject_hits
    if total_susp > 0:
        score += min(30, total_susp * 2)
        reasons.append(
            f"Suspicious strings: URLs={url_hits}, cmd/powershell={suspicious_strings_hits}, "
            f"registry={reg_hits}, network={net_hits}, crypto={crypto_hits}, injection={inject_hits}"
        )

    # Signature + Microsoft whitelist
    company = (version_info.get("company_name") or "").lower()
    signed = sig_info.get("signed", False)

    if signed:
        score -= 20
        reasons.append("Digital signature present (reduced score)")

    if "microsoft" in company:
        score -= 30
        reasons.append("CompanyName indicates Microsoft (system binary, reduced score)")

    # DLL whitelist
    dll_names = [imp["dll"] for imp in imports]
    if dll_names and all(d in SYSTEM_DLLS for d in dll_names):
        score -= 15
        reasons.append("Imports only standard Windows DLLs (reduced score)")

    # Section whitelist
    section_names = [s["name"] for s in sections]
    if section_names and all(name in STANDARD_SECTIONS for name in section_names):
        score -= 10
        reasons.append("Only standard PE sections (reduced score)")

    # Rich version info
    rich_vi = sum(1 for v in version_info.values() if v)
    if rich_vi >= 2:
        score -= 10
        reasons.append("Rich version info present (reduced score)")

    # VT integration
    if vt_result and vt_result.get("success"):
        mal = vt_result.get("malicious", 0)
        susp = vt_result.get("suspicious", 0)
        harmless = vt_result.get("harmless", 0)
        undetected = vt_result.get("undetected", 0)

        if mal > 0 or susp > 0:
            score = max(score, 80)
            reasons.append(
                f"VirusTotal: malicious={mal}, suspicious={susp} (strong indicator)"
            )
        elif mal == 0 and susp == 0 and (harmless + undetected) > 0:
            score -= 20
            reasons.append("VirusTotal: no detections (reduced score)")

    # Normalize
    score = max(0, min(score, 100))

    if score < 25:
        label = "LIKELY CLEAN"
    elif score < 60:
        label = "SUSPICIOUS"
    else:
        label = "HIGHLY SUSPICIOUS"

    return {"score": score, "label": label, "reasons": reasons}
