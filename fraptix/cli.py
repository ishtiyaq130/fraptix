import argparse
from pathlib import Path

from . import __version__
from .core.engine import RuleEngine
from .core.filter import filter_findings
from .core.parser import PythonParser
from .project.detector import ProjectDetector
from .project.scanner import FileScanner
from .reporters.console import ConsoleReporter
from .reporters.json import JSONReporter
from .rules.registry import get_all_rules


def main():
    parser = argparse.ArgumentParser(
        prog="fraptix",
        description="Frappe application code analyzer",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a Frappe application",
    )

    scan_parser.add_argument(
        "apps",
        nargs="+",
        help="Frappe application(s) to scan",
    )

    scan_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
        help="Show findings at or above this severity",
    )

    scan_parser.add_argument(
        "--category",
        choices=["security", "performance", "refactoring"],
        help="Filter findings by category",
    )

    scan_parser.add_argument(
        "--rule",
        dest="rule_id",
        help="Filter findings by rule ID",
    )

    scan_parser.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
        help="Output format",
    )

    args = parser.parse_args()

    if args.command != "scan":
        parser.print_help()
        return

    detector = ProjectDetector()
    scanner = FileScanner()
    python_parser = PythonParser()

    rules = get_all_rules()
    engine = RuleEngine(rules)

    if args.format == "json":
        reporter = JSONReporter()
    else:
        reporter = ConsoleReporter()

    try:
        # ---------------------------------------------------------
        # Detect Frappe bench
        # ---------------------------------------------------------

        project = detector.detect(Path.cwd())

        # ---------------------------------------------------------
        # Validate applications first
        # ---------------------------------------------------------

        app_paths = []

        for app_name in args.apps:
            app_path = detector.get_app_path(
                project,
                app_name,
            )

            app_paths.append(
                (app_name, app_path)
            )

        # ---------------------------------------------------------
        # Console header
        # ---------------------------------------------------------

        if args.format == "console":
            reporter.show_header()

        # ---------------------------------------------------------
        # Analyze applications
        # ---------------------------------------------------------

        for app_name, app_path in app_paths:

            # -----------------------------------------------------
            # Scan Python files
            # -----------------------------------------------------

            files = scanner.scan(app_path)

            # -----------------------------------------------------
            # Parse Python files
            # -----------------------------------------------------

            parse_results = [
                python_parser.parse(file_path)
                for file_path in files
            ]

            # -----------------------------------------------------
            # Parse statistics
            # -----------------------------------------------------

            parsed_files = [
                result
                for result in parse_results
                if result.success
            ]

            parse_errors = [
                result
                for result in parse_results
                if not result.success
            ]

            # -----------------------------------------------------
            # Run rules
            # -----------------------------------------------------

            findings = []

            for result in parsed_files:
                findings.extend(
                    engine.analyze(
                        result.tree,
                        result.path,
                    )
                )

            # -----------------------------------------------------
            # Apply filters
            # -----------------------------------------------------

            findings = filter_findings(
                findings,
                severity=args.severity,
                category=args.category,
                rule_id=args.rule_id,
            )

            # -----------------------------------------------------
            # Report
            # -----------------------------------------------------

            if args.format == "console":
                reporter.show_findings(findings)

                reporter.show_application(
                    bench_path=project.root,
                    app_name=app_name,
                    app_path=app_path,
                    file_count=len(files),
                    parsed_count=len(parsed_files),
                    parse_error_count=len(parse_errors),
                )

            else:
                reporter.show_report(
                    bench_path=project.root,
                    app_name=app_name,
                    app_path=app_path,
                    file_count=len(files),
                    parsed_count=len(parsed_files),
                    parse_error_count=len(parse_errors),
                    findings=findings,
                )

    except ValueError as error:
        if args.format == "console":
            reporter.show_error(str(error))
        else:
            reporter.show_error(str(error))

        raise SystemExit(1)


if __name__ == "__main__":
    main()