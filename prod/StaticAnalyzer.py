import ast
from typing import List, Dict, Any

# ==============================================================================
# StaticAnalyzer
#
# This class uses Python's built-in `ast` module and follows the `NodeVisitor`
# design pattern to perform static analysis on Python code.
#
# HOW IT WORKS:
# - The `ast` module parses source code into an Abstract Syntax Tree (AST).
# - The `NodeVisitor` class walks through each node of the AST.
# - For each node type (e.g., FunctionDef, If, Call), a method `visit_<NodeType>`
#   is automatically invoked if defined in this class.
#   Example: visiting a function call node → calls `visit_Call()`.
#
# - The `visit()` method dispatches automatically based on the node type,
#   so you only need to implement logic in the `visit_*` methods you care about.
#
# - This allows StaticAnalyzer to:
#   - Identify dangerous patterns (e.g., use of `eval`, `exec`, dynamic SQL)
#   - Perform taint tracking (propagate tainted variables)
#   - Analyze structural properties like control flow depth and error handling
#
# - Results of the analysis are collected in the `self.vulnerabilities` list,
#   which is returned at the end of analysis.
#
# Example usage:
#   analyzer = StaticAnalyzer()
#   results = analyzer.analyze(code_as_string)
#   features = generate_feature_vector(results)
#
# ==============================================================================
class StaticAnalyzer(ast.NodeVisitor):
    def __init__(self):
        # List to store detected vulnerabilities
        self.vulnerabilities: List[Dict[str, Any]] = []

        # Sources that can introduce untrusted user input
        self.sources = {"input", "sys.argv", "os.environ", "request"}

        # Dangerous functions that should be avoided or sanitized
        self.sinks = {
            "eval", "exec", "os.system",
            "subprocess.call", "subprocess.Popen",
            "cursor.execute"
        }

        # Set of variables marked as tainted (containing data coming from non-trusted sources)
        self.tainted_vars = set()

        # Context for current function being analyzed
        self.current_function = None

        # Control structure depth tracking
        self.control_depth = 0
        self.max_control_depth = 0

        # Error handling flags
        self.in_try_block = False
        self.has_try = {}  # function_name → bool

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Track the current function name and reset context
        self.current_function = node.name
        self.max_control_depth = 0
        self.control_depth = 0
        self.in_try_block = False
        self.has_try[node.name] = False

        # Visit all inner nodes
        self.generic_visit(node)

        # Check if error handling (try/except) is missing
        if not self.has_try[node.name]:
            self.vulnerabilities.append({
                "type": "Missing Error Handling",
                "function": node.name,
                "line": node.lineno
            })

        # Check for excessive nesting (e.g., > 3 levels)
        if self.max_control_depth > 3:
            self.vulnerabilities.append({
                "type": "Excessive Control Structure Nesting",
                "function": node.name,
                "depth": self.max_control_depth,
                "line": node.lineno
            })

    def visit_Try(self, node: ast.Try):
        # Mark current function as having error handling
        self.has_try[self.current_function] = True
        self.in_try_block = True
        self.generic_visit(node)
        self.in_try_block = False

    def visit_If(self, node: ast.If):
        # Increase depth of control structure and track max depth
        self.control_depth += 1
        self.max_control_depth = max(self.max_control_depth, self.control_depth)
        self.generic_visit(node)
        self.control_depth -= 1

    def visit_While(self, node: ast.While):
        # Same nesting logic for while loops
        self.control_depth += 1
        self.max_control_depth = max(self.max_control_depth, self.control_depth)
        self.generic_visit(node)
        self.control_depth -= 1

    def visit_For(self, node: ast.For):
        # Same nesting logic for for loops
        self.control_depth += 1
        self.max_control_depth = max(self.max_control_depth, self.control_depth)
        self.generic_visit(node)
        self.control_depth -= 1

    def visit_Assign(self, node: ast.Assign):
        # Handle assignment nodes, e.g., x = input()
        # Goal: detect if the right-hand side is a tainted source (like input())
        value = node.value

        # Check if the right-hand side of the assignment is a function call
        if isinstance(value, ast.Call):
            # Check if the function being called is a simple name (not an attribute like os.system)
            if isinstance(value.func, ast.Name):
                # Check if the function name is one of the known untrusted sources
                if value.func.id in self.sources:
                    # If so, mark the target variable on the left-hand side as tainted
                    for target in node.targets:
                        # We only mark simple variable names, not complex targets like tuples or lists
                        if isinstance(target, ast.Name):
                            # Add the variable to the set of tainted variables
                            self.tainted_vars.add(target.id)
                            # This variable now carries untrusted data from a source like input()

        # Continue walking the AST for any child nodes
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Determine full name of the function being called (module.func)
        func_name = self.get_full_func_name(node.func)

        # Check if the function is a known sink (dangerous call)
        if func_name in self.sinks:
            self.vulnerabilities.append({
                "type": "Dangerous Function Call",
                "function": func_name,
                "line": node.lineno
            })

        # Detect unsafe use of open() with tainted (user-controlled) file path
        if func_name == "open":
            # Check if at least one argument is passed to open()
            if node.args:
                arg0 = node.args[0]

                # Check if the first argument (file path) is a variable name
                if isinstance(arg0, ast.Name):
                    # If that variable was previously marked as tainted (e.g. user = input())
                    if arg0.id in self.tainted_vars:
                        # Then this use of open() is potentially unsafe
                        # because the path is user-controlled and could lead to:
                        # - Arbitrary file read/write
                        # - Path traversal attacks
                        self.vulnerabilities.append({
                            "type": "Tainted File Access (open)",
                            "function": func_name,
                            "line": node.lineno
                        })

        # Check if the function consists in deserialization
        if func_name == "pickle.load":
            self.vulnerabilities.append({
                "type": "Unsafe Deserialization",
                "function": func_name,
                "line": node.lineno
            })

            # Check if the function risks buffer overflow
            if func_name == "strcpy":
                self.vulnerabilities.append({
                    "type": "Copy without length control, Buffer Overflow risk",
                    "function": func_name,
                    "line": node.lineno
                })

        # Detect dynamic SQL queries constructed via string ops
        if func_name == "cursor.execute":
            if node.args and isinstance(node.args[0], (ast.BinOp, ast.JoinedStr)):
                self.vulnerabilities.append({
                    "type": "Dynamic SQL Query",
                    "line": node.lineno
                })

        # Check for tainted arguments passed to dangerous sinks
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
        # Return full function name for calls like os.system or plain eval
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}"
        return ""

    def analyze(self, code: str) -> List[Dict[str, Any]]:
        # Parse the code into AST and start the visit
        try:
            tree = ast.parse(code)
            self.visit(tree)
        except SyntaxError as e:
            return [{"error": f"Syntax error at line {e.lineno}: {e.text}"}]
        return self.vulnerabilities


def generate_feature_vector(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate a summary of vulnerability counts as feature vector.
    """
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
