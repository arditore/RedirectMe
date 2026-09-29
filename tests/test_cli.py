from rich.console import Console
from rich.table import Table

from redirectme.cli import _truncate, escape


def _render_markup(markup_text: str) -> str:
    """Renders a Rich-markup string exactly like the CLI does and returns the
    plain text that actually ends up on screen (styling stripped)."""
    console = Console(record=True, width=200)
    console.print(markup_text)
    return console.export_text()


def test_escape_neutralizes_rich_markup_injection():
    # A malicious scanned site could return a URL/link containing Rich markup
    # tags; escape() must make them render as literal text, not be interpreted
    # as styling (color, blink, hidden text...) in the live progress display
    # or the summary table.
    evil = "https://evil.example.com/[bold red]INJECTED[/bold red][blink]FAKE[/blink]"

    rendered_raw = _render_markup(evil)
    assert "[bold red]" not in rendered_raw  # unescaped: tags get interpreted away

    rendered_escaped = _render_markup(escape(evil))
    assert "[bold red]INJECTED[/bold red][blink]FAKE[/blink]" in rendered_escaped


def test_escape_neutralizes_injection_in_a_table_cell():
    evil_url = "https://evil.example.com/[green]SAFE — nothing to see[/green]"

    console = Console(record=True, width=200)
    table = Table()
    table.add_column("URL")
    table.add_row(escape(evil_url))
    console.print(table)

    rendered = console.export_text()
    assert "[green]SAFE" in rendered


def test_truncate_then_escape_preserves_injection_neutralization():
    # The progress bar truncates before escaping; make sure a malicious tag
    # that survives truncation is still neutralized once rendered.
    evil = "https://evil.example.com/" + "a" * 50 + "[bold red]INJECTED[/bold red]"
    truncated = _truncate(evil, max_len=90)
    assert "[bold red]" in truncated  # the tag itself must have survived truncation

    rendered = _render_markup(escape(truncated))
    assert "[bold red]" in rendered
