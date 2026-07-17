from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.theme import Theme

THEME = Theme(
    {
        "primary":   "bold bright_green",
        "accent":    "bold bright_cyan",
        "warning":   "bold yellow",
        "error":     "bold red",
        "dim_green": "dim green",
        "gold":      "bold yellow",
        "muted":     "dim white",
    }
)

console = Console(theme=THEME)

VERSION = "2.2.0"

# ── Landscape banner — ASCII art LEFT, info RIGHT, full width, centered ───────

_BANNER = """\
[bold bright_green]░█████╗░███████╗░██████╗░██╗░██████╗[/bold bright_green]   [bold white]Aegis-Devin · AI Autonomous Pentest + Network Forensics[/bold white]
[bold bright_green]██╔══██╗██╔════╝██╔════╝░██║██╔════╝[/bold bright_green]   [dim white]────────────────────────────────────────────────────────[/dim white]
[bold bright_green]███████║█████╗░░██║░░██╗░██║╚█████╗░[/bold bright_green]   [bold bright_cyan]recon[/bold bright_cyan] [dim white]·[/dim white] [bold bright_cyan]vuln[/bold bright_cyan] [dim white]·[/dim white] [bold bright_cyan]exploit[/bold bright_cyan] [dim white]·[/dim white] [bold bright_cyan]post[/bold bright_cyan] [dim white]·[/dim white] [bold bright_cyan]forensics[/bold bright_cyan] [dim white]·[/dim white] [bold bright_cyan]ai[/bold bright_cyan] [dim white]·[/dim white] [bold bright_cyan]report[/bold bright_cyan]
[bold bright_green]██╔══██║██╔══╝░░██║░░╚██╗██║░╚═══██╗[/bold bright_green]   [dim white]15+ modules  ·  10+ WAF vendors  ·  AI network forensics[/dim white]
[bold bright_green]██║░░██║███████╗╚██████╔╝██║██████╔╝[/bold bright_green]   [dim white]────────────────────────────────────────────────────────[/dim white]
[bold bright_green]╚═╝░░╚═╝╚══════╝░╚═════╝░╚═╝╚═════╝[/bold bright_green]   [bold yellow]$ aegis ai auto --target <host> --full[/bold yellow]
[dim green]                                      [/dim green]   [dim white]v{ver}  ·  MIT  ·  github.com/thecnical/aegis-devin[/dim white]
[dim green]⚔  One command. Every phase. Real AI. [/dim green]   [dim white]Author: Chandan Pandey  ·  ☕ buymeacoffee.com/chandanpandit[/dim white]"""


def show_banner(enabled: bool = True) -> None:
    if not enabled:
        return

    content = _BANNER.format(ver=VERSION)

    console.print()
    console.print(
        Panel(
            content,
            border_style="bright_green",
            padding=(0, 2),
            expand=True,
            title="[bold bright_green] ⚔  AEGIS  ⚔ [/bold bright_green]",
            title_align="center",
            subtitle="[dim green] For authorized use only [/dim green]",
            subtitle_align="center",
        )
    )
    console.print()
