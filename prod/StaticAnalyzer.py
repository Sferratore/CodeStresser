import ast
import builtins
from typing import List, Dict, Any, Set

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
        self.cfg: Dict[int, Set[int]] = {}
        self.line_to_call: Dict[int, tuple] = {}

    def build_cfg(self, tree: ast.AST) -> Dict[int, Set[int]]:
        edges: Dict[int, Set[int]] = {}

        def add_edge(src: int, dst: int | None):
            if dst is None:
                return
            edges.setdefault(src, set()).add(dst)

        def get_next_lineno(stmt_list: List[ast.stmt], index: int, parent_next: int | None) -> int | None:
            if index + 1 < len(stmt_list):
                return stmt_list[index + 1].lineno
            return parent_next

        def process_body(body: List[ast.stmt], next_lineno: int | None):
            prev_lineno: int | None = None
            for idx, stmt in enumerate(body):
                lineno = getattr(stmt, "lineno", None)
                if lineno is None:
                    continue
                if prev_lineno is not None:
                    add_edge(prev_lineno, lineno)

                if isinstance(stmt, ast.If):
                    next_after = get_next_lineno(body, idx, next_lineno)
                    body_first = stmt.body[0].lineno if stmt.body else next_after
                    orelse_first = stmt.orelse[0].lineno if stmt.orelse else next_after
                    add_edge(lineno, body_first)
                    add_edge(lineno, orelse_first)
                    process_body(stmt.body, next_after)
                    process_body(stmt.orelse, next_after)
                elif isinstance(stmt, (ast.For, ast.While)):
                    next_after = get_next_lineno(body, idx, next_lineno)
                    body_first = stmt.body[0].lineno if stmt.body else next_after
                    add_edge(lineno, body_first)
                    add_edge(lineno, next_after)
                    process_body(stmt.body, lineno)
                    if stmt.body:
                        last_body_line = stmt.body[-1].lineno
                        add_edge(last_body_line, lineno)
                elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    next_after = get_next_lineno(body, idx, next_lineno)
                    if stmt.body:
                        add_edge(lineno, stmt.body[0].lineno)
                    process_body(stmt.body, next_after)
                prev_lineno = lineno
            if prev_lineno is not None and next_lineno is not None:
                add_edge(prev_lineno, next_lineno)

        process_body(tree.body, None)
        return edges

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

    def _get_var_name(self, arg) -> str | None:
        if isinstance(arg, ast.Name):
            return arg.id
        return None

    def _detect_toctou(self):
        checks = {line: info for line, info in self.line_to_call.items() if info[0] == "check"}
        uses = {line: info for line, info in self.line_to_call.items() if info[0] == "use"}

        def reachable(start: int, target: int) -> bool:
            visited = set([start])
            stack = [start]
            while stack:
                cur = stack.pop()
                if cur == target:
                    return True
                for nxt in self.cfg.get(cur, []):
                    if nxt not in visited:
                        visited.add(nxt)
                        stack.append(nxt)
            return False

        for c_line, (_, _, c_arg) in checks.items():
            c_var = self._get_var_name(c_arg)
            if not c_var:
                continue
            for u_line, (kind, u_func, u_arg) in uses.items():
                if reachable(c_line, u_line):
                    u_var = self._get_var_name(u_arg)
                    if c_var == u_var:
                        self.vulnerabilities.append({
                            "type": "Potential TOCTOU",
                            "function": u_func,
                            "line": u_line
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
        if func_name in {"os.path.exists", "os.access", "os.stat"}:
            arg = node.args[0] if node.args else None
            self.line_to_call[node.lineno] = ("check", func_name, arg)
        elif func_name in {"open", "os.remove", "os.unlink", "os.rmdir"}:
            arg = node.args[0] if node.args else None
            self.line_to_call[node.lineno] = ("use", func_name, arg)

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
        elif isinstance(func, ast.Attribute):
            prefix = self.get_full_func_name(func.value)
            if prefix:
                return f"{prefix}.{func.attr}"
            return func.attr
        return ""

    def analyze(self, code: str) -> List[Dict[str, Any]]:
        try:
            tree = ast.parse(code)
            self.cfg = self.build_cfg(tree)
            self.visit(tree)
            self._detect_toctou()
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

def generate_feature_vector(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate a summary of vulnerability counts as feature vector.
    """
    feature_vector = {
        "generally_dangerous_calls": 0,
        "unprotected_critical_calls": 0,
        "tainted_input_in_dangerous_calls": 0,
        "tainted_param_source_calls": 0,
        "dangerous_dynamic_sql": 0,
        "tainted_flows": 0,
        "missing_error_handling": 0,
        "deep_control_nesting": 0,
        "uninitialized_variable_usage": 0,
        "tainted_file_access": 0,
        "unsafe_deserialization": 0,
        "buffer_overflow_risk": 0
    }

    for vuln in vulnerabilities:
        vtype = vuln.get("type")
        if vtype == "Generally Dangerous Function Call":
            feature_vector["generally_dangerous_calls"] += 1
        elif vtype == "Dangerous Function Call: Critical Sink Needing Try":
            feature_vector["unprotected_critical_calls"] += 1
        elif vtype == "Dangerous Function Call: Tainted Parameter Source":
            feature_vector["tainted_input_in_dangerous_calls"] += 1
        elif vtype == "Dangerous Function Call: Tainted Parameter Source":
            feature_vector["tainted_param_source_calls"] += 1
        elif vtype == "Dangerous Dynamic SQL Query":
            feature_vector["dangerous_dynamic_sql"] += 1
        elif vtype == "Tainted Data Flow to Dangerous Sink":
            feature_vector["tainted_flows"] += 1
        elif vtype == "Missing Error Handling":
            feature_vector["missing_error_handling"] += 1
        elif vtype == "Excessive Control Structure Nesting":
            feature_vector["deep_control_nesting"] += 1
        elif vtype == "Use of Uninitialized Variable":
            feature_vector["uninitialized_variable_usage"] += 1
        elif vtype == "Tainted File Access (open)":
            feature_vector["tainted_file_access"] += 1
        elif vtype == "Unsafe Deserialization":
            feature_vector["unsafe_deserialization"] += 1
        elif vtype == "Copy without length control, Buffer Overflow risk":
            feature_vector["buffer_overflow_risk"] += 1

    return feature_vector
