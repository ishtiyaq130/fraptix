import ast
from pathlib import Path

from fraptix.core.models import Finding, RuleCategory, Severity
from fraptix.core.rule import Rule


class PermissionBypassRule(Rule):
    rule_id = "SEC005"
    name = "Potential Frappe permission bypass"
    category = RuleCategory.SECURITY
    severity = Severity.HIGH

    DANGEROUS_APIS = {
        "get_all",
        "get_value",
        "get_single_value",
    }

    REQUEST_SOURCES = {
        "form_dict",
        "request",
    }

    def check(
        self,
        tree: ast.AST,
        file_path: Path,
    ) -> list[Finding]:

        findings = []

        for node in ast.walk(tree):
            if not isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue

            if not self._is_whitelisted(node):
                continue

            function_parameters = self._get_function_parameters(node)

            user_controlled_names = set(function_parameters)

            user_controlled_names.update(
                self._get_user_controlled_assignments(node)
            )

            has_permission_check = self._has_permission_check(node)
            user_controlled_names = set(function_parameters)

            user_controlled_names.update(
                self._get_user_controlled_assignments(node)
            )

            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue

                if not self._is_dangerous_db_call(child):
                    continue

                if not self._uses_user_controlled_input(
                    child,
                    user_controlled_names,
                ):
                    continue

                method = child.func.attr

                if has_permission_check:
                    finding_severity = Severity.MEDIUM
                    message = (
                        f"Whitelisted method uses frappe.db.{method}() "
                        "with user-controlled input, but an explicit "
                        "frappe.has_permission() check was detected. "
                        "Verify that the authorization check covers "
                        "the requested data."
                    )
                else:
                    finding_severity = Severity.HIGH
                    message = (
                        f"Whitelisted method uses frappe.db.{method}() "
                        "with user-controlled input and no explicit "
                        "frappe.has_permission() check was detected. "
                        "Verify that the caller is authorized to access "
                        "the requested data."
                    )

                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        name=self.name,
                        category=self.category,
                        severity=finding_severity,
                        file_path=file_path,
                        line=child.lineno,
                        column=child.col_offset,
                        message=message,
                    )
                )

        return findings

    def _get_user_controlled_assignments(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> set[str]:

        user_controlled_names = set()

        for child in ast.walk(node):
            if not isinstance(child, ast.Assign):
                continue

            if not self._is_request_source_expression(child.value):
                continue

            for target in child.targets:
                if isinstance(target, ast.Name):
                    user_controlled_names.add(target.id)

        return user_controlled_names

    def _is_request_source_expression(
        self,
        node: ast.AST,
    ) -> bool:

        if isinstance(node, ast.Attribute):
            if self._is_request_source(node):
                return True

        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                if self._is_request_source(child):
                    return True

        return False

    def _is_whitelisted(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:

        for decorator in node.decorator_list:

            # @frappe.whitelist
            if isinstance(decorator, ast.Attribute):
                if self._is_frappe_whitelist_attribute(decorator):
                    return True

            # @frappe.whitelist()
            if isinstance(decorator, ast.Call):
                if self._is_frappe_whitelist_call(decorator):
                    return True

        return False

    def _is_frappe_whitelist_attribute(
        self,
        node: ast.Attribute,
    ) -> bool:

        return (
            node.attr == "whitelist"
            and isinstance(node.value, ast.Name)
            and node.value.id == "frappe"
        )

    def _is_frappe_whitelist_call(
        self,
        node: ast.Call,
    ) -> bool:

        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "whitelist"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "frappe"
        )

    def _is_dangerous_db_call(
        self,
        node: ast.Call,
    ) -> bool:

        if not isinstance(node.func, ast.Attribute):
            return False

        if node.func.attr not in self.DANGEROUS_APIS:
            return False

        db = node.func.value

        if not isinstance(db, ast.Attribute):
            return False

        if db.attr != "db":
            return False

        frappe = db.value

        return (
            isinstance(frappe, ast.Name)
            and frappe.id == "frappe"
        )

    def _get_function_parameters(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> set[str]:

        parameters = set()

        for argument in node.args.posonlyargs:
            parameters.add(argument.arg)

        for argument in node.args.args:
            parameters.add(argument.arg)

        for argument in node.args.kwonlyargs:
            parameters.add(argument.arg)

        if node.args.vararg:
            parameters.add(node.args.vararg.arg)

        if node.args.kwarg:
            parameters.add(node.args.kwarg.arg)

        return parameters

    def _uses_user_controlled_input(
        self,
        node: ast.Call,
        function_parameters: set[str],
    ) -> bool:

        for argument in node.args:
            if self._is_user_controlled(argument, function_parameters):
                return True

        for keyword in node.keywords:
            if self._is_user_controlled(
                keyword.value,
                function_parameters,
            ):
                return True

        return False

    def _is_user_controlled(
        self,
        node: ast.AST,
        user_controlled_names: set[str],
    ) -> bool:

        if isinstance(node, ast.Name):
            return node.id in user_controlled_names

        if isinstance(node, ast.Attribute):
            return self._is_request_source(node)

        for child in ast.walk(node):

            if isinstance(child, ast.Name):
                if child.id in user_controlled_names:
                    return True

            if isinstance(child, ast.Attribute):
                if self._is_request_source(child):
                    return True

        return False

    def _is_request_source(
        self,
        node: ast.Attribute,
    ) -> bool:

        current = node

        while isinstance(current, ast.Attribute):
            current = current.value

        if not isinstance(current, ast.Name):
            return False

        if current.id != "frappe":
            return False

        attributes = []

        current = node

        while isinstance(current, ast.Attribute):
            attributes.append(current.attr)
            current = current.value

        attributes.reverse()

        return bool(
            attributes
            and attributes[0] in self.REQUEST_SOURCES
        )

    def _has_permission_check(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue

            if not isinstance(child.func, ast.Attribute):
                continue

            if child.func.attr != "has_permission":
                continue

            frappe = child.func.value

            if (
                isinstance(frappe, ast.Name)
                and frappe.id == "frappe"
            ):
                return True

        return False