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
        self.critical_functions_needing_try = {
            "eval", "exec",  # Code execution
            "os.system",  # System command execution
            "subprocess.call", "subprocess.Popen", "subprocess.run", "subprocess.check_call", "subprocess.check_output",
            # Process handling
            "open", "os.remove", "os.unlink",  # File operations
            "os.rename", "os.replace",  # File system changes
            "os.mkdir", "os.makedirs", "os.rmdir", "os.removedirs",  # Directory operations
            "shutil.copy", "shutil.copy2", "shutil.copytree", "shutil.move", "shutil.rmtree",
            # File and directory manipulation
            "json.load", "json.loads",  # Can raise decoding errors
            "pickle.load",  # Can raise EOFError or PickleError
            "int", "float",  # Conversion functions (can raise ValueError)
            "cursor.execute", "cursor.executemany"  # Database queries
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

        for target in node.targets:
            if isinstance(target, ast.Name):
                self.defined_vars.add(target.id)

        # === Case 1: direct input() ===
        if isinstance(value, ast.Call):
            if isinstance(value.func, ast.Name):
                if value.func.id in self.sources:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.tainted_vars.add(target.id)

        # === Case 2: request.GET[...] ===
        elif isinstance(value, ast.Subscript):
            if isinstance(value.value, ast.Attribute):
                attr = value.value
                if (
                        isinstance(attr.value, ast.Name) and attr.value.id == "request" and
                        attr.attr in {"GET", "POST", "args", "form"}
                ):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.tainted_vars.add(target.id)

        # === Case 3: assignment uses tainted variable (e.g., query = "..." + user_input) ===
        elif is_tainted_expr(value, self.tainted_vars, self.sources):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Determine full name of the function being called
        func_name = self.get_full_func_name(node.func)


        # --- Check for general dangerous calls ---
        if func_name in self.sinks:
            # These are always reported regardless of try/except
            self.vulnerabilities.append({
                "type": "Generally Dangerous Function Call",
                "function": func_name,
                "line": node.lineno
            })

        # --- Check for critical functions that requires try/except protection ---
        if func_name in self.critical_functions_needing_try:
            if not self.in_try_block:
                # Dangerous + unprotected: must be reported
                self.vulnerabilities.append({
                    "type": "Dangerous Function Call: Critical Sink Needing Try",
                    "function": func_name,
                    "line": node.lineno
                })

        # --- Check for tainted input passed to dangerous function call ---
        if func_name in self.sinks:
            for arg in node.args:
                # Case 1: direct call to a source like input()
                if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) and arg.func.id in self.sources:
                    self.vulnerabilities.append({
                        "type": "Dangerous Function Call: Tainted Parameter Source",
                        "sink": func_name,
                        "line": node.lineno
                    })

                # Case 2: variable that is tainted
                elif isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                    self.vulnerabilities.append({
                        "type": "Dangerous Function Call: Tainted Parameter Source",
                        "sink": func_name,
                        "line": node.lineno
                    })

                # Case 3: expression composed with tainted input (e.g., "SELECT " + user_input)
                elif isinstance(arg, (ast.BinOp, ast.JoinedStr)) and is_tainted_expr(arg, self.tainted_vars, self.sources):
                    self.vulnerabilities.append({
                        "type": "Dangerous Function Call: Tainted Parameter Source",
                        "sink": func_name,
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

        # --- Dynamic SQL Detection ---
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if node.args:
                sql_arg = node.args[0]
                # Case 1: inline dynamic SQL construction containing a tainted-something (e.g., "SELECT..." + input())
                if isinstance(sql_arg, (ast.BinOp, ast.JoinedStr)) and is_tainted_expr(sql_arg, self.tainted_vars, self.sources):
                    self.vulnerabilities.append({
                        "type": "Dangerous Dynamic SQL Query",
                        "line": node.lineno
                    })
                # Case 2: variable passed as query and is tainted
                elif isinstance(sql_arg, ast.Name) and sql_arg.id in self.tainted_vars:
                    self.vulnerabilities.append({
                        "type": "Dangerous Dynamic SQL Query",
                        "line": node.lineno
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
        #if isinstance(node.ctx, ast.Load):
            # If the variable has not been defined earlier (via assignment)
            # and it's not marked as tainted input, we report it as a potential issue.
            # self.vulnerabilities.append({
                #"type": "Use of Uninitialized Variable",
                #"variable": node.id,
                #"line": node.lineno
            #})

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

def is_tainted_expr(expr, tainted_vars, vulnerable_sources):
    # Case 1: The expression is a variable (Name node)
    # We return True if the variable is in the set of tainted variables
    if isinstance(expr, ast.Name):
        return expr.id in tainted_vars

    # Case 2: The expression is a binary operation (e.g., a + b)
    # We recursively check both the left and right operands.
    # If either side is tainted, the result is considered tainted.
    elif isinstance(expr, ast.BinOp):
        return is_tainted_expr(expr.left, tainted_vars, vulnerable_sources) or is_tainted_expr(expr.right, tainted_vars, vulnerable_sources)

    # Case 3: The expression is a function call (e.g., input())
    # We treat direct calls to certain known input functions as tainted.
    elif isinstance(expr, ast.Call):
        if isinstance(expr.func, ast.Name):
            return expr.func.id in vulnerable_sources  # Extend this set if needed

    # Case 4: The expression is a formatted string (f-string)
    # JoinedStr contains a list of values; if any of them are tainted, the whole string is tainted
    elif isinstance(expr, ast.JoinedStr):
        return any(is_tainted_expr(value, tainted_vars) for value in expr.values)

    # Default case: expression is not recognized as tainted
    return False
