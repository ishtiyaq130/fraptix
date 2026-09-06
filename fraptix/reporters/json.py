import json


class JSONReporter:

    def show_header(self):
        pass

    def show_findings(self, findings):
        pass

    def show_application(
        self,
        *,
        bench_path,
        app_name,
        app_path,
        file_count,
        parsed_count,
        parse_error_count,
    ):
        pass

    def show_report(
        self,
        *,
        bench_path,
        app_name,
        app_path,
        file_count,
        parsed_count,
        parse_error_count,
        findings,
    ):
        data = {
            "tool": "fraptix",
            "version": "0.1.0",
            "application": app_name,
            "bench": str(bench_path),
            "path": str(app_path),
            "summary": {
                "python_files": file_count,
                "parsed": parsed_count,
                "parse_errors": parse_error_count,
                "findings": len(findings),
            },
            "findings": [
                self._serialize_finding(finding)
                for finding in findings
            ],
        }

        print(json.dumps(data, indent=2))

    def _serialize_finding(self, finding):
        return {
            "rule_id": finding.rule_id,
            "name": finding.name,
            "category": finding.category.value,
            "severity": finding.severity.value,
            "file": str(finding.file_path),
            "line": finding.line,
            "column": finding.column,
            "message": finding.message,
        }
    
    def show_error(self, message):
        import json

        print(
            json.dumps(
                {
                    "tool": "fraptix",
                    "version": __version__,
                    "error": message,
                },
                indent=2,
            )
        )