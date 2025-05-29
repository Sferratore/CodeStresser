import ast
import builtins
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
#   so it's only needed to implement logic in the `visit_*` methods that need check.
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

        # Set of variables that have been assigned a value (to detect use-before-def)
        self.defined_vars = set()

        # Dictionary of critical calls that are not handled by try block.
        # Will contain function name as key and a list of occurrences (sink, line of code) as tuples  as values.
        self.critical_calls_outside_try = {}

        # Sources that can introduce untrusted user input
        self.sources = {"input", "sys.argv", "os.environ", "request"}

        # Dangerous functions that should be avoided or sanitized
        self.sinks = {
            "eval", "exec", "os.system",
            "subprocess.call", "subprocess.Popen",
            "cursor.execute"
        }

        # Critical sinks that require try/except for runtime protection
        self.critical_sinks_needing_try = {
            "eval", "exec", "os.system", "subprocess.call", "subprocess.Popen"
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

        # List of builtin names of calls/functions (print...ecc.)
        self.builtins = set(dir(builtins))

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Track the current function name and reset context
        self.current_function = node.name
        self.max_control_depth = 0
        self.control_depth = 0
        self.in_try_block = False

        # Add function parameters to defined_vars so they're not flagged
        for arg in node.args.args:
            self.defined_vars.add(arg.arg)

        # Visit all inner nodes
        self.generic_visit(node)

        # Check for excessive nesting (e.g., > 3 levels)
        if self.max_control_depth > 3:
            self.vulnerabilities.append({
                "type": "Excessive Control Structure Nesting",
                "function": node.name,
                "depth": self.max_control_depth,
                "line": node.lineno
            })

    def visit_Try(self, node: ast.Try):
        # Save the current try-context flag so it can be restored later
        old = self.in_try_block

        # We are now inside a try block — set the flag to True
        self.in_try_block = True

        # Recursively visit all child nodes inside the try block
        # This ensures that any dangerous calls made here will be marked as protected
        self.generic_visit(node)

        # Restore the previous try-context flag after exiting the try block
        self.in_try_block = old

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
        value = node.value

        # Iterate over all targets on the left-hand side of the assignment
        # For example, in `x = 1`, the target is `x`.
        for target in node.targets:
            # We only track simple variable assignments (not tuples, lists, etc.)
            if isinstance(target, ast.Name):
                # Mark the variable as "defined"
                # This allows us to detect later if a variable is used before being initialized
                self.defined_vars.add(target.id)

        # === Case 1: direct call like input() ===

        # Check if the right-hand side of the assignment is a function call
        if isinstance(value, ast.Call):
            # Check if the function being called is a simple (non-namespaced) function
            # Example: input() → ast.Name(id="input")
            if isinstance(value.func, ast.Name):
                # Check if the function is one of the known untrusted sources (e.g., input, os.environ, request)
                if value.func.id in self.sources:
                    # For each target on the left-hand side of the assignment
                    for target in node.targets:
                        # We only handle simple variables (not tuples, object attributes, etc.)
                        if isinstance(target, ast.Name):
                            # Mark this variable as "tainted", meaning it contains data from an untrusted source
                            # This is used later for taint analysis (e.g., if this variable flows into a sink)
                            self.tainted_vars.add(target.id)

        # Case 2: request.GET[...] or request.POST[...]
        elif isinstance(value, ast.Subscript): # ast.Subscript represent access to value using index or key
            # Check if it's something like: request.GET[...] or request.POST[...]
            if isinstance(value.value, ast.Attribute): # ast.Attribute checks access to attribute or propriety
                attr = value.value
                # Ensure the base object of the attribute is 'request' (i.e., attr.value.id == "request")
                # and the accessed attribute is one of the known user input sources
                if (
                        isinstance(attr.value, ast.Name) and attr.value.id == "request" and
                        attr.attr in {"GET", "POST", "args", "form"}  # These are common user input dictionaries
                ):
                    # Now we are confident this is something like: request.GET['x']
                    # We iterate over all variables being assigned on the left-hand side
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            # Mark the target variable as tainted — it holds user-supplied data
                            self.tainted_vars.add(target.id)
                            # Example: query = request.GET['q'] → 'query' is now tracked as tainted

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Determine full name of the function being called
        func_name = self.get_full_func_name(node.func)

        # --- Check for critical sink that requires try/except protection ---
        if func_name in self.critical_sinks_needing_try:
            if not self.in_try_block:
                # Dangerous + unprotected: must be reported
                self.vulnerabilities.append({
                    "type": "Unprotected Critical Function Call",
                    "function": func_name,
                    "line": node.lineno
                })

        # --- Check for general dangerous calls that don't require try ---
        if func_name in self.sinks:
            # These are always reported regardless of try/except
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
            # We are only interested in arguments that are variable names (e.g., exec(user_input))
            if isinstance(arg, ast.Name):
                # Check if this variable has been marked as tainted (from input, os.environ, etc.)
                if arg.id in self.tainted_vars:
                    # If the function receiving this tainted variable is a known dangerous sink
                    if func_name in self.sinks:
                        # Then this represents a potential vulnerability:
                        # user-controlled data is flowing into a critical operation
                        self.vulnerabilities.append({
                            "type": "Tainted Data Flow to Dangerous Sink",
                            "sink": func_name,  # e.g., 'exec', 'os.system', 'eval'
                            "line": node.lineno  # line number of the call
                        })

        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        # If this 'Name' node is part of a function call expression,
        # for example: print("hello") → 'print' is a Name inside a Call node.
        # We check two things:
        # 1. The parent node must be of type 'ast.Call'.
        # 2. This node must be the one being called — that is, it must be the 'func' field of the Call.
        #    (not an argument like 'x' in foo(x), but the function name itself: 'foo')
        #
        # This is important because we don't want to falsely report built-in or user-defined functions
        # like 'print', 'len', 'my_function' as uninitialized variables.
        #
        # So if this node is being used as a function call (not a variable read),
        # we skip it from the uninitialized variable check.
        if isinstance(getattr(node, 'parent', None), ast.Call) and node is getattr(node.parent, 'func', None):
            return

        # Skip checking for built-in function names like 'print', 'len', etc.
        # These are always available and should not be reported as undefined.
        if node.id in self.builtins:
            return

        # We are only interested in variables being used (not defined),
        # so we check if the context is 'Load' (read usage).
        if isinstance(node.ctx, ast.Load):
            # If the variable has not been defined earlier (via assignment)
            # and it's not marked as tainted input, we report it as a potential issue.
            self.vulnerabilities.append({
                "type": "Use of Uninitialized Variable",
                "variable": node.id,
                "line": node.lineno
            })

        # Continue visiting any child nodes of this Name node.
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
