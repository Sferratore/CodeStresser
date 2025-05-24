import ast
from typing import List, Dict, Any
import json
import pandas as pd


class StaticAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.sources = {"input", "sys.argv", "os.environ", "request"}
        self.sinks = {"eval", "exec", "os.system", "subprocess.call", "subprocess.Popen", "open", "cursor.execute"}
        self.tainted_vars = set()
        self.current_function = None
        self.control_depth = 0
        self.max_control_depth = 0
        self.in_try_block = False
        self.has_try = {}

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.current_function = node.name
        self.max_control_depth = 0
        self.control_depth = 0
        self.in_try_block = False
        self.has_try[node.name] = False
        self.generic_visit(node)

        if not self.has_try[node.name]:
            self.vulnerabilities.append({
                "type": "Missing Error Handling",
                "function": node.name,
                "line": node.lineno
            })

        if self.max_control_depth > 3:
            self.vulnerabilities.append({
                "type": "Excessive Control Structure Nesting",
                "function": node.name,
                "depth": self.max_control_depth,
                "line": node.lineno
            })

    def visit_Try(self, node: ast.Try):
        self.has_try[self.current_function] = True
        self.in_try_block = True
        self.generic_visit(node)
        self.in_try_block = False

    def visit_If(self, node: ast.If):
        self.control_depth += 1
        self.max_control_depth = max(self.max_control_depth, self.control_depth)
        self.generic_visit(node)
        self.control_depth -= 1

    def visit_While(self, node: ast.While):
        self.control_depth += 1
        self.max_control_depth = max(self.max_control_depth, self.control_depth)
        self.generic_visit(node)
        self.control_depth -= 1

    def visit_For(self, node: ast.For):
        self.control_depth += 1
        self.max_control_depth = max(self.max_control_depth, self.control_depth)
        self.generic_visit(node)
        self.control_depth -= 1

    def visit_Assign(self, node: ast.Assign):
        value = node.value
        if isinstance(value, ast.Call):
            if isinstance(value.func, ast.Name) and value.func.id in self.sources:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self.get_full_func_name(node.func)

        if func_name in self.sinks:
            self.vulnerabilities.append({
                "type": "Dangerous Function Call",
                "function": func_name,
                "line": node.lineno
            })

        if func_name == "cursor.execute":
            if node.args and isinstance(node.args[0], (ast.BinOp, ast.JoinedStr)):
                self.vulnerabilities.append({
                    "type": "Dynamic SQL Query",
                    "line": node.lineno
                })

        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                if func_name in self.sinks:
                    self.vulnerabilities.append({
                        "type": "Tainted Data Flow to Dangerous Sink",
                        "sink": func_name,
                        "line": node.lineno
                    })

        self.generic_visit(node)

    def get_full_func_name(self, func) -> str:
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}"
        return ""

    def analyze(self, code: str) -> List[Dict[str, Any]]:
        try:
            tree = ast.parse(code)
            self.visit(tree)
        except SyntaxError as e:
            return [{"error": f"Syntax error at line {e.lineno}: {e.text}"}]
        return self.vulnerabilities


def generate_feature_vector(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    feature_vector = {
        "dangerous_function_calls": 0,
        "dynamic_sql_queries": 0,
        "tainted_flows": 0,
        "missing_error_handling": 0,
        "deep_control_nesting": 0
    }

    for vuln in vulnerabilities:
        if vuln["type"] == "Dangerous Function Call":
            feature_vector["dangerous_function_calls"] += 1
        elif vuln["type"] == "Dynamic SQL Query":
            feature_vector["dynamic_sql_queries"] += 1
        elif vuln["type"] == "Tainted Data Flow to Dangerous Sink":
            feature_vector["tainted_flows"] += 1
        elif vuln["type"] == "Missing Error Handling":
            feature_vector["missing_error_handling"] += 1
        elif vuln["type"] == "Excessive Control Structure Nesting":
            feature_vector["deep_control_nesting"] += 1

    return feature_vector