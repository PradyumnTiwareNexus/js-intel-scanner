"""
CLI entrypoint.

Usage:
  python -m backend.cli detect-tools
  python -m backend.cli pipeline
  python -m backend.cli scan example.com
  python -m backend.cli scan example.com --profile deep
  python -m backend.cli scan example.com --disable amass --disable nuclei
  python -m backend.cli scan -f domains.txt
  python -m backend.cli set-key <gemini_api_key>
"""
import asyncio
from pathlib import Path
import typer
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn

from backend.core.config import Config, detect_all_tools
from backend.core.orchestrator import run_pipeline
from backend.core.report import export_all

app = typer.Typer(help="JS Intelligence & Sensitive Information Mining Platform")
console = Console()


@app.command("detect-tools")
def detect_tools_cmd():
    """First-run wizard: detect all required external binaries."""
    cfg = Config.load()
    results = detect_all_tools(cfg)
    for tool, path in results.items():
        if path:
            console.print(f"[green]✓[/green] {tool}: {path}")
        else:
            console.print(f"[red]✗[/red] {tool}: NOT FOUND — install it or set path manually")
    missing = [t for t, p in results.items() if not p]
    if missing:
        console.print(f"\n[yellow]Missing tools:[/yellow] {', '.join(missing)}")
        console.print("Set paths manually in configs/config.yaml under tool_paths, "
                       "or install the binaries and re-run this command.")


@app.command("set-key")
def set_key(gemini_api_key: str):
    """Store Gemini API key in config."""
    cfg = Config.load()
    cfg.gemini_api_key = gemini_api_key
    cfg.save()
    console.print("[green]Gemini API key saved.[/green]")


@app.command("settings")
def show_settings():
    """Print current configuration."""
    cfg = Config.load()
    console.print(cfg)


@app.command("pipeline")
def show_pipeline():
    """Print the effective stage order and enabled/disabled state for the active profile."""
    cfg = Config.load()
    console.print(f"[bold]Active profile:[/bold] {cfg.active_profile}\n")
    effective = set(cfg.effective_pipeline())
    for name in cfg.pipeline:
        enabled = name in effective
        marker = "[green]✓[/green]" if enabled else "[dim]✗ disabled[/dim]"
        console.print(f"  {marker} {name}")


@app.command("scan")
def scan(
    domain: str = typer.Argument(None, help="Target domain, e.g. example.com"),
    file: str = typer.Option(None, "-f", "--file", help="File with list of domains, one per line"),
    output: str = typer.Option("exports", "-o", "--output", help="Output base directory"),
    profile: str = typer.Option(None, "--profile", help="Named profile from configs/config.yaml, e.g. fast/balanced/deep/stealth"),
    disable: list[str] = typer.Option([], "--disable", help="Stage name to disable for this run only (repeatable)"),
    only: list[str] = typer.Option([], "--only", help="Restrict the run to just these stages, in their configured relative order (repeatable)"),
):
    """Run the recon -> JS extraction -> secret scan pipeline.

    Examples:
      python -m backend.cli scan example.com --profile deep
      python -m backend.cli scan example.com --disable amass --disable nuclei
      python -m backend.cli scan example.com --only httpx --only jsfinder --only regex
    """
    cfg = Config.load()

    if profile:
        if profile not in cfg.profiles:
            console.print(f"[red]Unknown profile '{profile}'. Available: {', '.join(cfg.profiles)}[/red]")
            raise typer.Exit(1)
        cfg.active_profile = profile

    if only:
        unknown = [s for s in only if s not in cfg.stages]
        if unknown:
            console.print(f"[red]Unknown stage(s) in --only: {', '.join(unknown)}[/red]")
            raise typer.Exit(1)
        cfg.pipeline = [s for s in cfg.pipeline if s in only]

    for stage_name in disable:
        if stage_name not in cfg.stages:
            console.print(f"[yellow]Warning: --disable references unknown stage '{stage_name}', ignoring[/yellow]")
            continue
        cfg.stages.setdefault(stage_name, {})["enabled"] = False

    domains = []
    if domain:
        domains.append(domain)
    if file:
        domains += [line.strip() for line in Path(file).read_text().splitlines() if line.strip()]
    if not domains:
        console.print("[red]Provide a domain or -f domains.txt[/red]")
        raise typer.Exit(1)

    base_dir = Path(output)

    for d in domains:
        console.print(f"\n[bold cyan]Scanning {d}[/bold cyan]")
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(), TextColumn("{task.percentage:>3.0f}%"),
        ) as progress:
            task_id = progress.add_task(d, total=100)

            def on_event(stage, pct, msg):
                if pct >= 0:
                    progress.update(task_id, completed=pct, description=f"{d} — {stage}")
                # verbose per-line logs are intentionally not printed to keep CLI clean;
                # they're available for a future websocket/live-log consumer.

            summary = asyncio.run(run_pipeline(d, cfg, base_dir, on_event))

        out_dir = base_dir / d.replace("/", "_") / "report"
        paths = export_all(summary, out_dir)
        console.print(f"[green]Done.[/green] Findings: {len(summary['findings'])}")
        console.print(f"  HTML: {paths['html']}")
        console.print(f"  JSON: {paths['json']}")
        if paths["csv"]:
            console.print(f"  CSV:  {paths['csv']}")


if __name__ == "__main__":
    app()
