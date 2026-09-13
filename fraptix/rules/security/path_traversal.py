import ast
from pathlib import Path

from fraptix.core.models import Finding, RuleCategory, Severity
from fraptix.core.rule import Rule


class PathTraversalRule(Rule):
    rule_id = "SEC006"
    name = "Potential path traversal"
    category = RuleCategory.SECURITY
    severity = Severity.HIGH

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

            user_controlled_names = self._get_function_parameters(node)

            user_controlled_names.update(
                self._get_user_controlled_assignments(
                    node,
                    user_controlled_names,
                )
            )

            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue

                if not self._is_open_call(child):
                    continue

                if not child.args:
                    continue

                file_path_argument = child.args[0]

                if not self._is_user_controlled(
                    file_path_argument,
                    user_controlled_names,
                ):
                    continue

                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=file_path,
                        line=child.lineno,
                        column=child.col_offset,
                        message=(
                            "Whitelisted method uses open() with "
                            "user-controlled file path. Verify that "
                            "the path is validated and restricted to "
                            "an allowed directory to prevent path traversal."
                        ),
                    )
                )

        return findings

    def _is_whitelisted(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:

        for decorator in node.decorator_list:

            if isinstance(decorator, ast.Attribute):
                if (
                    decorator.attr == "whitelist"
                    and isinstance(decorator.value, ast.Name)
                    and decorator.value.id == "frappe"
                ):
                    return True

            if isinstance(decorator, ast.Call):
                if (
                    isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "whitelist"
                    and isinstance(decorator.func.value, ast.Name)
                    and decorator.func.value.id == "frappe"
                ):
                    return True

        return False

    def _is_open_call(
        self,
        node: ast.Call,
    ) -> bool:

        return (
            isinstance(node.func, ast.Name)
            and node.func.id == "open"
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

    def _get_user_controlled_assignments(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        user_controlled_names: set[str],
    ) -> set[str]:

        user_controlled_names = set(user_controlled_names)

        changed = True

        while changed:
            changed = False

            for child in ast.walk(node):
                if not isinstance(child, ast.Assign):
                    continue

                # Direct request input:
                #
                # path = frappe.form_dict.path
                #
                if self._contains_request_source(child.value):
                    is_user_controlled = True
                else:
                    # Indirect input:
                    #
                    # path = "/tmp/" + filename
                    # path = os.path.join("/tmp", filename)
                    #
                    is_user_controlled = self._is_user_controlled(
                        child.value,
                        user_controlled_names,
                    )

                if not is_user_controlled:
                    continue

                for target in child.targets:
                    if not isinstance(target, ast.Name):
                        continue

                    if target.id not in user_controlled_names:
                        user_controlled_names.add(target.id)
                        changed = True

        return user_controlled_names

    def _contains_request_source(
        self,
        node: ast.AST,
    ) -> bool:

        for child in ast.walk(node):

            if not isinstance(child, ast.Attribute):
                continue

            if self._is_request_source(child):
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