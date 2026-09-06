from collections import defaultdict
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


class ConsoleReporter:
    """Render Fraptix output in the terminal."""

    def __init__(self):
        self.console = Console()

    def show_header(self):
        self.console.print()

        self.console.print(
            Panel.fit(
                "[bold cyan]FRAPTIX[/bold cyan]\n"
                "[dim]Frappe Security • Performance • Refactoring Analyzer[/dim]",
                border_style="cyan",
                padding=(1, 4),
            )
        )

    def show_application(
        self,
        bench_path,
        app_name,
        app_path,
        file_count,
        parsed_count,
        parse_error_count,
    ):
        table = Table(
            show_header=False,
            box=None,
            padding=(0, 2),
        )

        table.add_column(
            style="bold cyan",
            width=18,
        )
        table.add_column(
            style="white",
        )

        table.add_row(
            "Bench",
            str(bench_path),
        )

        table.add_row(
            "Application",
            f"[bold green]{app_name}[/bold green]",
        )

        table.add_row(
            "Path",
            str(app_path),
        )

        table.add_row(
            "Python files",
            f"[bold yellow]{file_count}[/bold yellow]",
        )

        table.add_row(
            "Parsed",
            f"[bold green]{parsed_count}[/bold green]",
        )

        table.add_row(
            "Parse errors",
            (
                f"[bold red]{parse_error_count}[/bold red]"
                if parse_error_count
                else "[bold green]0[/bold green]"
            ),
        )

        self.console.print(table)
        self.console.print()

        self.console.print(
            "[bold green]✓[/bold green] "
            "[green]Application analysis completed[/green]"
        )

        self.console.print()
    
    def show_findings(self, findings):
        if not findings:
            self.console.print(
                "[bold green]✓[/bold green] "
                "[green]No issues found[/green]"
            )
            self.console.print()
            return

        grouped = defaultdict(list)

        for finding in findings:
            grouped[finding.category].append(finding)

        self.console.print(
            "[bold]Findings[/bold]"
        )
        self.console.print()

        for category, category_findings in grouped.items():
            category_name = category.value.upper()

            self.console.print(
                f"[bold cyan]{category_name}[/bold cyan]"
            )
            self.console.print(
                "─" * 60
            )

            for finding in category_findings:
                self._show_finding(finding)

            self.console.print()

    def _show_finding(self, finding):
        severity_styles = {
            "critical": "bold red",
            "high": "bold red",
            "medium": "bold yellow",
            "low": "bold blue",
        }

        severity = finding.severity.value
        severity_style = severity_styles.get(
            severity,
            "bold white",
        )

        self.console.print(
            f"[{severity_style}]✗ {severity.upper()}[/{severity_style}]  "
            f"[bold]{finding.rule_id}[/bold]  "
            f"{finding.name}"
        )

        self.console.print(
            f"  [dim]{finding.file_path}:{finding.line}[/dim]"
        )

        self.console.print(
            f"  {finding.message}"
        )

        self.console.print()

    def show_summary(self, rules_count, findings_count):
        table = Table(
            title="Analysis Summary",
            box=None,
            padding=(0, 2),
        )

        table.add_column(
            "Metric",
            style="bold cyan",
        )

        table.add_column(
            "Value",
            justify="right",
        )

        table.add_row(
            "Rules executed",
            f"[bold yellow]{rules_count}[/bold yellow]",
        )

        if findings_count:
            findings_value = (
                f"[bold red]{findings_count}[/bold red]"
            )
        else:
            findings_value = (
                "[bold green]0[/bold green]"
            )

        table.add_row(
            "Issues found",
            findings_value,
        )

        self.console.print(table)
        self.console.print()

    def show_error(self, message):
        self.console.print(
            Panel(
                f"[bold red]✗[/bold red] {message}",
                title="[bold red]Error[/bold red]",
                border_style="red",
            )
        )