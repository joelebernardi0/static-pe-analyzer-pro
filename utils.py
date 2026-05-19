from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from datetime import datetime
import json
import os

console = Console()

BANNER = r"""
███████╗██████╗ ███████╗ █████╗ ████████╗██╗ ██████╗ 
██╔════╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║██╔════╝ 
█████╗  ██████╔╝█████╗  ███████║   ██║   ██║██║      
██╔══╝  ██╔══██╗██╔══╝  ██╔══██║   ██║   ██║██║      
███████╗██║  ██║███████╗██║  ██║   ██║   ██║╚██████╗ 
╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ 
"""

def print_title(subtitle: str):
    banner_text = Text(BANNER, style="bold green")
    sub = Text(f"\n{subtitle}\n", style="bold magenta")
    content = Text.assemble(banner_text, sub)
    console.print(Panel(content, border_style="cyan", title="[bold cyan]Static PE Analyzer PRO[/bold cyan]"))


def print_hashes(hashes: dict):
    table = Table(title="[bold cyan]File Hashes[/bold cyan]", show_lines=True, style="bright_black")
    table.add_column("Type", style="bold magenta")
    table.add_column("Value", style="bright_green")

    for htype, value in hashes.items():
        table.add_row(htype.upper(), value)

    console.print(table)


def print_basic_info(info: dict, version_info: dict, sig_info: dict, vt_result: dict | None):
    table = Table(title="[bold cyan]PE Basic Info[/bold cyan]", show_lines=True, style="bright_black")
    table.add_column("Field", style="bold magenta")
    table.add_column("Value", style="bright_green")

    for k, v in info.items():
        table.add_row(k, str(v))

    table.add_row("CompanyName", str(version_info.get("company_name")))
    table.add_row("FileDescription", str(version_info.get("file_description")))
    table.add_row("ProductName", str(version_info.get("product_name")))
    table.add_row("Signed", "Yes" if sig_info.get("signed") else "No")

    console.print(table)

    if vt_result:
        if vt_result.get("success"):
            vt_table = Table(title="[bold cyan]VirusTotal[/bold cyan]", show_lines=True, style="bright_black")
            vt_table.add_column("Metric", style="bold magenta")
            vt_table.add_column("Value", style="bright_green")
            vt_table.add_row("Malicious", str(vt_result.get("malicious", 0)))
            vt_table.add_row("Suspicious", str(vt_result.get("suspicious", 0)))
            vt_table.add_row("Harmless", str(vt_result.get("harmless", 0)))
            vt_table.add_row("Undetected", str(vt_result.get("undetected", 0)))
            vt_table.add_row("Link", vt_result.get("link", "N/A"))
            console.print(vt_table)
        else:
            console.print(f"[yellow]VirusTotal lookup failed:[/yellow] {vt_result.get('error')}")


def print_sections(sections: list):
    table = Table(title="[bold cyan]Sections[/bold cyan]", show_lines=True, style="bright_black")
    table.add_column("Name", style="bold magenta")
    table.add_column("Virtual Size", style="bright_green")
    table.add_column("Raw Size", style="bright_green")
    table.add_column("Entropy", style="bright_green")
    table.add_column("Characteristics", style="bright_green")

    for s in sections:
        table.add_row(
            s["name"],
            str(s["virtual_size"]),
            str(s["raw_size"]),
            str(s["entropy"]),
            s["characteristics"],
        )

    console.print(table)


def print_imports(imports: list):
    if not imports:
        console.print("[yellow]No imports found.[/yellow]")
        return

    for entry in imports:
        panel_text = Text()
        panel_text.append(f"DLL: {entry['dll']}\n", style="bold magenta")
        for func in entry["functions"]:
            panel_text.append(f"  - {func}\n", style="bright_green")
        console.print(Panel(panel_text, border_style="magenta"))


def print_exports(exports: list):
    if not exports:
        console.print("[yellow]No exports found.[/yellow]")
        return

    table = Table(title="[bold cyan]Exports[/bold cyan]", show_lines=True, style="bright_black")
    table.add_column("Function", style="bright_green")
    for e in exports:
        table.add_row(e)
    console.print(table)


def print_strings(strings: list, limit: int = 50):
    console.print(f"[bold magenta]Showing first {limit} strings (total: {len(strings)})[/bold magenta]")
    for s in strings[:limit]:
        console.print(f"[bright_green]{s}[/bright_green]")


def print_suspicious_score(score_data: dict):
    score = score_data["score"]
    label = score_data["label"]
    reasons = score_data["reasons"]

    if label == "LIKELY CLEAN":
        color = "green"
    elif label == "SUSPICIOUS":
        color = "yellow"
    else:
        color = "red"

    text = Text()
    text.append(f"SUSPICIOUS SCORE: {score}/100\n", style=f"bold {color}")
    text.append(f"Classification: {label}\n\n", style=f"bold {color}")

    if reasons:
        text.append("Reasons:\n", style="bold magenta")
        for r in reasons:
            text.append(f"  - {r}\n", style="bright_green")
    else:
        text.append("No strong suspicious indicators detected.\n", style="bright_green")

    console.print(Panel(text, border_style=color))


def save_report_txt(report_text: str, output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"report_{timestamp}.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_text)
    return filename


def save_report_json(report_data: dict, output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"report_{timestamp}.json")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)
    return filename
