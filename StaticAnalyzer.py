import ast
from typing import List, Dict, Any


class StaticAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.dangerous_functions = {"eval", "exec", "compile"}
        self.dangerous_modules = {
            ("os", "system"),
            ("subprocess", "call"),
            ("subprocess", "Popen"),
            ("pickle", "load")
        }

    def visit_Call(self, node: ast.Call):
        # Rilevamento funzioni pericolose built-in
        if isinstance(node.func, ast.Name) and node.func.id in self.dangerous_functions:
            self.vulnerabilities.append({
                "type": "Dangerous Function Call",
                "function": node.func.id,
                "line": node.lineno
            })

        # Rilevamento chiamate pericolose da moduli
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module_func = (node.func.value.id, node.func.attr)
            if module_func in self.dangerous_modules:
                self.vulnerabilities.append({
                    "type": "Dangerous Module Call",
                    "function": f"{module_func[0]}.{module_func[1]}",
                    "line": node.lineno
                })

        # Rilevamento SQL dinamico via concatenazione o f-string
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if node.args and isinstance(node.args[0], (ast.BinOp, ast.JoinedStr)):
                self.vulnerabilities.append({
                    "type": "Dynamic SQL Query",
                    "function": "execute",
                    "line": node.lineno
                })

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Rilevamento assenza di try/except nella funzione
        has_try_except = any(isinstance(n, ast.Try) for n in ast.walk(node))
        if not has_try_except:
            self.vulnerabilities.append({
                "type": "Missing Error Handling",
                "function": node.name,
                "line": node.lineno
            })
        self.generic_visit(node)

    def analyze(self, code: str) -> List[Dict[str, Any]]:
        try:
            tree = ast.parse(code)
            self.visit(tree)
        except SyntaxError as e:
            return [{"error": f"Syntax error at line {e.lineno}: {e.text}"}]
        return self.vulnerabilities

