import os
import argparse
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from analyzer import (
    compute_hashes,
    load_pe,
    get_basic_info,
    get_sections_info,
    get_imports,
    get_exports,
    extract_strings,
    get_version_info,
    get_signature_info,
    compute_suspicious_score,
)
from utils import (
    print_title,
    print_hashes,
    print_basic_info,
    print_sections,
    print_imports,
    print_exports,
    print_strings,
    print_suspicious_score,
    save_report_txt,
    save_report_json,
)
from vt import vt_lookup

console = Console()


def analyze_file(file_path: str, use_vt: bool = True):
    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[bold green]Scanning PE file...[/bold green] {task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("Loading PE...", total=None)

        pe = load_pe(file_path)
        hashes = compute_hashes(file_path)
        basic = get_basic_info(pe)
        sections = get_sections_info(pe)
        imports = get_imports(pe)
        exports = get_exports(pe)
        strings = extract_strings(file_path, min_length=4)
        version_info = get_version_info(pe)
        sig_info = get_signature_info(pe)

        vt_result = None
        if use_vt:
            progress.update(task, description="Querying VirusTotal...")
            vt_result = vt_lookup(hashes["sha256"])

        score_data = compute_suspicious_score(sections, imports, strings, version_info, sig_info, vt_result)

        progress.update(task, description="Done")

    return {
        "file_path": file_path,
        "hashes": hashes,
        "basic": basic,
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "strings": strings,
        "version_info": version_info,
        "sig_info": sig_info,
        "vt_result": vt_result,
        "score_data": score_data,
    }


def build_text_report(analysis: dict) -> str:
    lines = []
    lines.append("Static PE Analyzer PRO Report")
    lines.append(f"File: {analysis['file_path']}")
    lines.append("=" * 60)

    lines.append("\n[HASHES]")
    for k, v in analysis["hashes"].items():
        lines.append(f"{k.upper()}: {v}")

    lines.append("\n[BASIC INFO]")
    for k, v in analysis["basic"].items():
        lines.append(f"{k}: {v}")
    vi = analysis["version_info"]
    si = analysis["sig_info"]
    lines.append(f"CompanyName: {vi.get('company_name')}")
    lines.append(f"FileDescription: {vi.get('file_description')}")
    lines.append(f"ProductName: {vi.get('product_name')}")
    lines.append(f"Signed: {'Yes' if si.get('signed') else 'No'}")

    vt = analysis["vt_result"]
    if vt:
        lines.append("\n[VIRUSTOTAL]")
        if vt.get("success"):
            lines.append(f"Malicious: {vt.get('malicious', 0)}")
            lines.append(f"Suspicious: {vt.get('suspicious', 0)}")
            lines.append(f"Harmless: {vt.get('harmless', 0)}")
            lines.append(f"Undetected: {vt.get('undetected', 0)}")
            lines.append(f"Link: {vt.get('link', 'N/A')}")
        else:
            lines.append(f"Error: {vt.get('error')}")

    lines.append("\n[SECTIONS]")
    for s in analysis["sections"]:
        lines.append(
            f"{s['name']} | VSize={s['virtual_size']} | RSize={s['raw_size']} | "
            f"Entropy={s['entropy']} | Char={s['characteristics']}"
        )

    lines.append("\n[IMPORTS]")
    for entry in analysis["imports"]:
        lines.append(f"DLL: {entry['dll']}")
        for func in entry["functions"]:
            lines.append(f"  - {func}")

    lines.append("\n[EXPORTS]")
    for e in analysis["exports"]:
        lines.append(f"- {e}")

    sd = analysis["score_data"]
    lines.append("\n[SUSPICIOUS SCORE]")
    lines.append(f"Score: {sd['score']}/100")
    lines.append(f"Classification: {sd['label']}")
    if sd["reasons"]:
        lines.append("Reasons:")
        for r in sd["reasons"]:
            lines.append(f"  - {r}")

    lines.append("\n[STRINGS] (first 100)")
    for s in analysis["strings"][:100]:
        lines.append(s)

    return "\n".join(lines)


def main_menu():
    print_title("STATIC PE ANALYZER // PRO MODE")

    file_path = console.input("[bold cyan]Enter path to PE file (.exe/.dll): [/bold cyan]").strip()
    if not os.path.isfile(file_path):
        console.print("[red]File not found. Exiting.[/red]")
        return

    analysis = analyze_file(file_path, use_vt=True)

    while True:
        console.print(
            Panel(
                "[bold magenta]1[/bold magenta] - Show hashes\n"
                "[bold magenta]2[/bold magenta] - Show basic PE info + VT\n"
                "[bold magenta]3[/bold magenta] - Show sections\n"
                "[bold magenta]4[/bold magenta] - Show imports\n"
                "[bold magenta]5[/bold magenta] - Show exports\n"
                "[bold magenta]6[/bold magenta] - Show strings (preview)\n"
                "[bold magenta]7[/bold magenta] - Show suspicious score\n"
                "[bold magenta]8[/bold magenta] - Generate full report (TXT + JSON)\n"
                "[bold magenta]0[/bold magenta] - Exit",
                title="[bold cyan]Menu[/bold cyan]",
                border_style="cyan",
            )
        )

        choice = console.input("[bold cyan]Select an option (0-8): [/bold cyan]").strip()

        if choice == "1":
            print_hashes(analysis["hashes"])
        elif choice == "2":
            print_basic_info(
                analysis["basic"],
                analysis["version_info"],
                analysis["sig_info"],
                analysis["vt_result"],
            )
        elif choice == "3":
            print_sections(analysis["sections"])
        elif choice == "4":
            print_imports(analysis["imports"])
        elif choice == "5":
            print_exports(analysis["exports"])
        elif choice == "6":
            print_strings(analysis["strings"], limit=50)
        elif choice == "7":
            print_suspicious_score(analysis["score_data"])
        elif choice == "8":
            txt = build_text_report(analysis)
            txt_path = save_report_txt(txt)
            json_path = save_report_json(analysis)
            console.print(f"[green]TXT report saved to:[/green] {txt_path}")
            console.print(f"[green]JSON report saved to:[/green] {json_path}")
        elif choice == "0":
            console.print("[yellow]Exiting...[/yellow]")
            break
        else:
            console.print("[red]Invalid choice.[/red]")


def cli_mode(file_path: str, no_vt: bool):
    if not os.path.isfile(file_path):
        console.print("[red]File not found.[/red]")
        return

    print_title("STATIC PE ANALYZER // PRO MODE (CLI)")
    analysis = analyze_file(file_path, use_vt=not no_vt)
    print_hashes(analysis["hashes"])
    print_basic_info(
        analysis["basic"],
        analysis["version_info"],
        analysis["sig_info"],
        analysis["vt_result"],
    )
    print_sections(analysis["sections"])
    print_suspicious_score(analysis["score_data"])

    txt = build_text_report(analysis)
    txt_path = save_report_txt(txt)
    json_path = save_report_json(analysis)
    console.print(f"[green]TXT report saved to:[/green] {txt_path}")
    console.print(f"[green]JSON report saved to:[/green] {json_path}")


def parse_args():
    parser = argparse.ArgumentParser(description="Static PE Analyzer PRO")
    parser.add_argument("--scan", help="Path to PE file to scan (CLI mode)")
    parser.add_argument("--no-vt", action="store_true", help="Disable VirusTotal lookup")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.scan:
        cli_mode(args.scan, args.no_vt)
    else:
        main_menu()
