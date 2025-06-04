import ast
import builtins
from typing import List, Dict, Any

class StaticAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.defined_vars = set()
        self.sources = {"input", "sys.argv", "os.environ", "request"}
        self.sinks = {
            "eval", "exec", "os.system",
            "subprocess.call", "subprocess.Popen",
            "cursor.execute"
        }
        self.critical_functions_needing_try = {
            "eval", "exec", "os.system",
            "subprocess.call", "subprocess.Popen", "subprocess.run",
            "subprocess.check_call", "subprocess.check_output",
            "open", "os.remove", "os.unlink",
            "os.rename", "os.replace", "os.mkdir", "os.makedirs",
            "os.rmdir", "os.removedirs",
            "shutil.copy", "shutil.copy2", "shutil.copytree",
            "shutil.move", "shutil.rmtree",
            "json.load", "json.loads",
            "pickle.load",
            "int", "float",
            "cursor.execute", "cursor.executemany"
        }
        self.tainted_vars = set()
        self.current_function = None
        self.control_depth = 0
        self.max_control_depth = 0
        self.in_try_block = False
        self.builtins = set(dir(builtins))

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.current_function = node.name
        self.max_control_depth = 0
        self.control_depth = 0
        self.in_try_block = False
        for arg in node.args.args:
            self.defined_vars.add(arg.arg)
        self.generic_visit(node)
        if self.max_control_depth > 3:
            self.vulnerabilities.append({
                "type": "Excessive Control Structure Nesting",
                "function": node.name,
                "depth": self.max_control_depth,
                "line": node.lineno
            })

    def visit_Try(self, node: ast.Try):
        old = self.in_try_block
        self.in_try_block = True
        self.generic_visit(node)
        self.in_try_block = old

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
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.defined_vars.add(target.id)

        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            if value.func.id in self.sources:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)

        elif isinstance(value, ast.Subscript):
            if isinstance(value.value, ast.Attribute):
                attr = value.value
                if isinstance(attr.value, ast.Name) and attr.value.id == "request" and attr.attr in {"GET", "POST", "args", "form"}:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.tainted_vars.add(target.id)

        elif is_tainted_expr(value, self.tainted_vars, self.sources):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self.get_full_func_name(node.func)

        if func_name in self.sinks:
            self.vulnerabilities.append({
                "type": "Generally Dangerous Function Call",
                "function": func_name,
                "line": node.lineno
            })

        if func_name in self.critical_functions_needing_try and not self.in_try_block:
            self.vulnerabilities.append({
                "type": "Dangerous Function Call: Critical Sink Needing Try",
                "function": func_name,
                "line": node.lineno
            })

        if func_name in self.sinks and func_name != "open":
            for arg in node.args:
                if (
                    (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) and arg.func.id in self.sources)
                    or (isinstance(arg, ast.Name) and arg.id in self.tainted_vars)
                    or (isinstance(arg, (ast.BinOp, ast.JoinedStr)) and is_tainted_expr(arg, self.tainted_vars, self.sources))
                ):
                    self.vulnerabilities.append({
                        "type": "Dangerous Function Call: Tainted Parameter Source",
                        "sink": func_name,
                        "line": node.lineno
                    })

        if func_name == "open" and node.args:
            arg0 = node.args[0]
            if isinstance(arg0, ast.Name) and arg0.id in self.tainted_vars:
                self.vulnerabilities.append({
                    "type": "Tainted File Access (open)",
                    "function": func_name,
                    "line": node.lineno
                })

        if func_name == "pickle.load":
            self.vulnerabilities.append({
                "type": "Unsafe Deserialization",
                "function": func_name,
                "line": node.lineno
            })

        if func_name == "strcpy":
            self.vulnerabilities.append({
                "type": "Copy without length control, Buffer Overflow risk",
                "function": func_name,
                "line": node.lineno
            })

        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if node.args:
                sql_arg = node.args[0]
                if isinstance(sql_arg, (ast.BinOp, ast.JoinedStr)) and is_tainted_expr(sql_arg, self.tainted_vars, self.sources):
                    self.vulnerabilities.append({
                        "type": "Dangerous Dynamic SQL Query",
                        "line": node.lineno
                    })
                elif isinstance(sql_arg, ast.Name) and sql_arg.id in self.tainted_vars:
                    self.vulnerabilities.append({
                        "type": "Dangerous Dynamic SQL Query",
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


def is_tainted_expr(expr, tainted_vars, vulnerable_sources):
    if isinstance(expr, ast.Name):
        return expr.id in tainted_vars
    elif isinstance(expr, ast.BinOp):
        return is_tainted_expr(expr.left, tainted_vars, vulnerable_sources) or is_tainted_expr(expr.right, tainted_vars, vulnerable_sources)
    elif isinstance(expr, ast.Call):
        if isinstance(expr.func, ast.Name):
            return expr.func.id in vulnerable_sources
    elif isinstance(expr, ast.JoinedStr):
        return any(is_tainted_expr(value, tainted_vars, vulnerable_sources) for value in expr.values)
    return False
