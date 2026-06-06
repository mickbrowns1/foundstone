"""
cli.py — FoundStone command-line interface.

Usage examples
--------------
  python cli.py run --rules 50 --source Okta
  python cli.py run --rule-id <uuid>
  python cli.py run --all --confirm-poc
  python cli.py verify --lookback 5m
  python cli.py list-sources
  python cli.py show-rule "AWS CloudTrail Enumeration"
  python cli.py clean
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from foundstone.config import load_config
from foundstone.classifier import classify
from foundstone.rule_parser import parse_pair_list
from foundstone.verifier import get_alert_counts

console = Console()

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

_DATA_PATH = Path(__file__).parent / "data" / "extracted.json"


def _load_rules() -> list[dict[str, Any]]:
    """Load and return all rules from extracted.json."""
    if not _DATA_PATH.exists():
        console.print(f"[red]ERROR[/] Cannot find {_DATA_PATH}")
        sys.exit(1)
    with _DATA_PATH.open() as fh:
        data = json.load(fh)
    # Support both {"results": [...]} and [...]
    return data["results"] if isinstance(data, dict) else data


def _find_rules(
    rules: list[dict[str, Any]],
    *,
    rule_id: str | None = None,
    source: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Filter the rule list according to CLI arguments."""
    if rule_id:
        matched = [r for r in rules if r.get("id") == rule_id]
        if not matched:
            console.print(f"[red]No rule found with id '{rule_id}'[/]")
            sys.exit(1)
        return matched

    if source:
        source_lower = source.lower()
        rules = [
            r for r in rules
            if any(
                source_lower in str(p.get("value", "")).lower()
                for q in r.get("queries", [])
                for p in q.get("pair_list", [])
                if p.get("key") == "dataSource.name"
            )
        ]

    if limit:
        rules = rules[:limit]

    return rules


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.option("--debug", is_flag=True, help="Enable verbose debug logging.")
def cli(debug: bool) -> None:
    """FoundStone — SentinelOne detection rule verifier."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

@cli.command("run")
@click.option("--rules", "limit", type=int, default=None, help="Max rules to run.")
@click.option("--source", default=None, help="Filter rules by dataSource.name.")
@click.option("--rule-id", default=None, help="Run a single rule by UUID.")
@click.option("--all", "run_all", is_flag=True, help="Run every rule (use carefully).")
@click.option(
    "--confirm-poc",
    is_flag=True,
    default=False,
    help="Bypass production URL safety check.",
)
def cmd_run(
    limit: int | None,
    source: str | None,
    rule_id: str | None,
    run_all: bool,
    confirm_poc: bool,
) -> None:
    """Run FoundStone for selected rules: ingest synthetic events and verify alerts."""
    from foundstone.runner import run_rules

    if not run_all and not rule_id and not limit and not source:
        console.print("[yellow]Hint:[/] Specify --rules N, --source X, --rule-id, or --all")
        raise click.Abort()

    cfg = load_config(confirm_poc=confirm_poc)
    all_rules = _load_rules()
    rules = _find_rules(all_rules, rule_id=rule_id, source=source, limit=limit if not run_all else None)

    console.print(f"[bold]Running FoundStone on {len(rules)} rule(s)[/] …\n")

    results: list[dict[str, Any]] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Processing rules …", total=len(rules))

        def _on_progress(idx: int, total: int, result: dict) -> None:
            status_color = {
                "ingested": "green",
                "dry_run": "cyan",
                "no_template": "yellow",
                "error": "red",
            }.get(result["status"], "white")
            progress.update(
                task,
                advance=1,
                description=f"[{status_color}]{result['status']:12}[/] {result['rule_name'][:60]}",
            )
            results.append(result)

        for _ in run_rules(rules, cfg, progress_callback=_on_progress):
            pass  # side-effects handled in callback

    _print_results_table(results)
    _print_summary(results)


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

@cli.command("verify")
@click.option(
    "--lookback",
    default="5m",
    show_default=True,
    help="Look-back window, e.g. 5m, 30m, 2h.",
)
@click.option("--confirm-poc", is_flag=True, default=False)
def cmd_verify(lookback: str, confirm_poc: bool) -> None:
    """Query SDL and show recent alert counts (no ingestion)."""
    cfg = load_config(confirm_poc=confirm_poc)
    seconds = _parse_duration(lookback)
    console.print(f"[bold]Querying alerts for the last {lookback} …[/]\n")
    counts = get_alert_counts(cfg, lookback_seconds=seconds)

    if not counts:
        console.print("[yellow]No alerts found in the specified window.[/]")
        return

    table = Table(title=f"Alerts — last {lookback}", show_lines=True)
    table.add_column("Rule / Title", style="cyan")
    table.add_column("Count", justify="right", style="magenta")

    for title, count in sorted(counts.items(), key=lambda x: -x[1]):
        table.add_row(title, str(count))

    console.print(table)


# ---------------------------------------------------------------------------
# list-sources
# ---------------------------------------------------------------------------

@cli.command("list-sources")
def cmd_list_sources() -> None:
    """Show all unique data sources and how many rules reference each."""
    rules = _load_rules()
    source_counts: dict[str, int] = {}

    for rule in rules:
        for query in rule.get("queries", []):
            for pair in query.get("pair_list", []):
                if pair.get("key") == "dataSource.name":
                    src = str(pair.get("value", "unknown"))
                    source_counts[src] = source_counts.get(src, 0) + 1

    table = Table(title="Data Sources", show_lines=True)
    table.add_column("Source", style="cyan")
    table.add_column("Rules", justify="right", style="magenta")

    for src, count in sorted(source_counts.items(), key=lambda x: -x[1]):
        table.add_row(src, str(count))

    console.print(table)
    console.print(f"\n[bold]{len(source_counts)}[/] unique sources across [bold]{len(rules)}[/] rules.")


# ---------------------------------------------------------------------------
# show-rule
# ---------------------------------------------------------------------------

@cli.command("show-rule")
@click.argument("name_or_id")
def cmd_show_rule(name_or_id: str) -> None:
    """Show parsed details for a rule matching NAME_OR_ID (substring or exact UUID)."""
    rules = _load_rules()
    noi_lower = name_or_id.lower()

    matches = [
        r for r in rules
        if noi_lower in r.get("id", "").lower() or noi_lower in r.get("name", "").lower()
    ]

    if not matches:
        console.print(f"[red]No rules matched '{name_or_id}'.[/]")
        sys.exit(1)

    for rule in matches[:5]:  # cap at 5 results
        rule_class, copies = classify(rule)
        queries = rule.get("queries", [])
        parsed = parse_pair_list(queries[0].get("pair_list", [])) if queries else None

        console.rule(f"[bold]{rule['name']}[/]")
        console.print(f"  [dim]ID:[/]          {rule.get('id')}")
        console.print(f"  [dim]App:[/]         {rule.get('app')}")
        console.print(f"  [dim]File:[/]        {rule.get('file')}")
        console.print(f"  [dim]Class:[/]       {rule_class}  (copies={copies})")
        console.print(f"  [dim]Source:[/]      {parsed.data_source if parsed else 'N/A'}")
        console.print()

        if parsed:
            console.print("  [bold]Required fields:[/]")
            for k, v in parsed.required.items():
                console.print(f"    {k} = {v!r}")
            if parsed.excluded:
                console.print("  [bold]Excluded fields:[/]")
                for k, v in parsed.excluded.items():
                    console.print(f"    {k} != {v!r}")

        console.print()


# ---------------------------------------------------------------------------
# clean
# ---------------------------------------------------------------------------

@cli.command("clean")
@click.option("--confirm-poc", is_flag=True, default=False)
@click.confirmation_option(prompt="This will query for _foundstone_test events. Continue?")
def cmd_clean(confirm_poc: bool) -> None:
    """
    Show instructions for cleaning up FoundStone synthetic events from SDL.

    SDL does not expose a delete-events API; we instead provide the PowerQuery
    you can run in the SDL console to identify and scope the test events.
    """
    console.print(
        "\n[bold]To identify FoundStone test events in SDL, run this query:[/]\n"
    )
    console.print(
        "  [cyan]_foundstone_test = 'True' | group n=count() by _rule_id, dataSource.name[/]\n"
    )
    console.print(
        "[yellow]SDL does not support event deletion via API.[/]\n"
        "Contact your SDL administrator to purge test data if needed,\n"
        "or use the session name filter ('foundstone-*') in the Data Retention settings."
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_duration(s: str) -> int:
    """Parse a duration string like '5m', '2h', '30s' into seconds."""
    s = s.strip().lower()
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    if s.endswith("s"):
        return int(s[:-1])
    return int(s)  # bare number assumed to be seconds


def _print_results_table(results: list[dict[str, Any]]) -> None:
    table = Table(title="FoundStone Results", show_lines=True)
    table.add_column("Rule", style="cyan", max_width=50)
    table.add_column("Class", style="blue")
    table.add_column("Source")
    table.add_column("Copies", justify="right")
    table.add_column("Status")
    table.add_column("Fired?", justify="center")
    table.add_column("Alerts", justify="right")

    STATUS_COLOR = {
        "ingested": "green",
        "dry_run": "cyan",
        "no_template": "yellow",
        "error": "red",
    }

    for r in results:
        fired = r.get("alert_fired")
        fired_str = "✓" if fired is True else ("✗" if fired is False else "—")
        fired_color = "green" if fired else ("red" if fired is False else "dim")
        status = r.get("status", "error")
        table.add_row(
            r.get("rule_name", ""),
            r.get("class", ""),
            r.get("template_source") or "—",
            str(r.get("copies", 1)),
            f"[{STATUS_COLOR.get(status, 'white')}]{status}[/]",
            f"[{fired_color}]{fired_str}[/]",
            str(r.get("alert_count", 0)),
        )

    console.print(table)


def _print_summary(results: list[dict[str, Any]]) -> None:
    total = len(results)
    ingested = sum(1 for r in results if r["status"] == "ingested")
    fired = sum(1 for r in results if r.get("alert_fired") is True)
    no_tmpl = sum(1 for r in results if r["status"] == "no_template")
    errors = sum(1 for r in results if r["status"] == "error")

    console.print(
        f"\n[bold]Summary:[/] {total} rules — "
        f"[green]{ingested} ingested[/], "
        f"[green]{fired} alerts fired[/], "
        f"[yellow]{no_tmpl} no template[/], "
        f"[red]{errors} errors[/]"
    )


if __name__ == "__main__":
    cli()
