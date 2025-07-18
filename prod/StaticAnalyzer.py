import ast
import builtins
from typing import List, Dict, Any
from radon.complexity import cc_visit

# StaticAnalyzer is a security-focused static analysis engine.
#
# Currently, it analyzes AST (Abstract Syntax Tree) and CFG (Control Flow Graph) of the code.
# It uses the visitor pattern by defining visit_* methods (e.g., visit_Assign, visit_Call),
# which are automatically dispatched by ast.NodeVisitor when corresponding AST nodes are encountered.
# The CFG analysis happens separately to the visitor AST logic.
#
# This hybrid AST/CFG analysis allows it to detect various vulnerabilities.

class StaticAnalyzer(ast.NodeVisitor):
    def __init__(self):

        # Vulnerability analysis
        self.vulnerabilities: List[Dict[str, Any]] = []  # List to store detected vulnerabilities
        self.tainted_vars = set()  # Variables tainted by untrusted sources
        self.defined_vars = set()  # Variables defined in the code

        # Analysis context tracking
        self.current_function = None  # Currently analyzed function
        self.control_depth = 0  # Current control flow nesting depth
        self.max_control_depth = 0  # Maximum control depth reached
        self.in_try_block = False  # Whether currently inside a try block

        # Security elements
        self.sources = {  # Sources of untrusted input
            "input", "sys.argv", "os.environ", "request"
        }
        self.sinks = {  # Sensitive sink functions (where tainted data can be dangerous)
            "eval", "exec", "os.system",
            "subprocess.call", "subprocess.Popen",
            "cursor.execute"
        }
        self.critical_functions_needing_try = {  # Critical functions that should be wrapped in try/except blocks
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

        # Python built-ins
        self.builtins = set(dir(builtins))  # Set of all Python built-in functions and objects. Will use to reference python built-ins and list vulns.

    # === AST METHODS ===

    # Method that is executed each time a function/method definition is visited inside the AST.
    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Attribute initialization
        self.current_function = node.name
        self.max_control_depth = 0
        self.control_depth = 0
        self.in_try_block = False

        # Adding each function argument to defined variables
        for arg in node.args.args:
            self.defined_vars.add(arg.arg)

        # Visits sub-nodes of the function
        self.generic_visit(node)

        # Checking for depth vulnerability
        if self.max_control_depth > 3:
            self.vulnerabilities.append({
                "type": "Excessive Control Structure Nesting",
                "function": node.name,
                "depth": self.max_control_depth,
                "line": node.lineno
            })

    # Method that is executed each time a try-catch block is visited inside the AST.
    def visit_Try(self, node: ast.Try):
        old = self.in_try_block
        self.in_try_block = True
        self.generic_visit(node)
        self.in_try_block = old

    # Method that is executed each time an if(else-elif) block is visited inside the AST.
    def visit_If(self, node: ast.If):
        self.control_depth += 1
        self.max_control_depth = max(self.max_control_depth, self.control_depth)
        self.generic_visit(node)
        self.control_depth -= 1

    # Method that is executed each time a while block is visited inside the AST.
    def visit_While(self, node: ast.While):
        self.control_depth += 1
        self.max_control_depth = max(self.max_control_depth, self.control_depth)
        self.generic_visit(node)
        self.control_depth -= 1

    # Method that is executed each time a for cycle is visited inside the AST.
    def visit_For(self, node: ast.For):
        self.control_depth += 1
        self.max_control_depth = max(self.max_control_depth, self.control_depth)
        self.generic_visit(node)
        self.control_depth -= 1

    # Method that is executed each time an assignment is visited inside the AST.
    def visit_Assign(self, node: ast.Assign):
        # Get the value being assigned (not used here, but accessible if needed)
        value = node.value

        # Iterate over all assignment targets (e.g., a, b = 1, 2 → two targets)
        for target in node.targets:
            # Check if the target is a simple variable name (not an attribute or subscript)
            if isinstance(target, ast.Name):
                # Add the variable name to the set of defined variables
                self.defined_vars.add(target.id)

        # In case the value of assignment is a method/function call, we check for the functions
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            # If the method/function comes from untrusted input (self.sources) we mark the variable as tainted
            if value.func.id in self.sources:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)

        # The assigned value is a subscript operation (e.g., something[...]).
        # We're specifically looking for cases like: request.GET['key']
        elif isinstance(value, ast.Subscript):
            # The subscript is being applied to an attribute, e.g., request.GET
            if isinstance(value.value, ast.Attribute):
                attr = value.value
                # Now check if the base of the attribute is a variable named 'request'
                # and the attribute being accessed is a common input source like GET, POST, args, or form.
                # These are typical user-controlled dictionaries in web frameworks (e.g., Flask, Django).
                if (
                        isinstance(attr.value, ast.Name) and
                        attr.value.id == "request" and
                        attr.attr in {"GET", "POST", "args", "form"}
                ):
                    # If all conditions match, we assume this assignment extracts user input
                    # into a local variable, which makes the variable tainted (i.e., potentially unsafe).
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            # Mark the variable on the left-hand side as tainted
                            self.tainted_vars.add(target.id)

        # We mark the assignment variable(s) as tainted if the value source is also tainted.
        elif self.is_tainted_expr(value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)

        # Continuing visiting nodes...
        self.generic_visit(node)

    # Method that is executed each time a function/method call is visited inside the AST.
    def visit_Call(self, node: ast.Call):
        func_name = self.get_full_func_name(node.func)

        # Checks for dangerous functions in case the function called is a sink
        if func_name in self.sinks:
            self.vulnerabilities.append({
                "type": "Generally Dangerous Function Call",
                "function": func_name,
                "line": node.lineno
            })

        # Checks for function needing try and if they are in a try block
        if func_name in self.critical_functions_needing_try and not self.in_try_block:
            self.vulnerabilities.append({
                "type": "Dangerous Function Call: Critical Sink Needing Try",
                "function": func_name,
                "line": node.lineno
            })

        # Checks if a sink is executed with tainted sources of data
        if func_name in self.sinks:
            for arg in node.args:
                if (
                        # Condition 1: The argument is a function call (e.g., input()) and the function name is in the set of taint sources
                        (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) and arg.func.id in self.sources)
                        # Condition 2: The argument is a variable, and that variable is already marked as tainted
                        or (isinstance(arg, ast.Name) and arg.id in self.tainted_vars)
                        # Condition 3: The argument is an expression (binary operation or f-string), and the expression is tainted
                        or (isinstance(arg, (ast.BinOp, ast.JoinedStr)) and self.is_tainted_expr(arg))
                ):
                    self.vulnerabilities.append({
                        "type": "Dangerous Function Call: Tainted Parameter Source",
                        "sink": func_name,
                        "line": node.lineno
                    })

        # Check if the function being called is 'pickle.load', which is known to be unsafe when deserializing untrusted input
        if func_name == "pickle.load":
            self.vulnerabilities.append({
                "type": "Unsafe Deserialization",
                "function": func_name,
                "line": node.lineno
            })

        # Check if the function being called is a method named "execute"
        # (e.g., cursor.execute(...)), which indicates a potential SQL execution
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            # Ensure that the function has at least one argument (typically the SQL query)
            if node.args:
                sql_arg = node.args[0]  # Extract the first argument of the execute() call

                # Case 1: The argument is a binary operation (e.g., string concatenation)
                # or a formatted string (f-string), and it's tainted (e.g., includes user input)
                if isinstance(sql_arg, (ast.BinOp, ast.JoinedStr)) and self.is_tainted_expr(sql_arg):
                    self.vulnerabilities.append({
                        "type": "Dangerous Dynamic SQL Query",  # Vulnerability type for reporting
                        "line": node.lineno  # Line number where it occurs
                    })

                # Case 2: The argument is a variable name that has been previously marked as tainted
                elif isinstance(sql_arg, ast.Name) and sql_arg.id in self.tainted_vars:
                    self.vulnerabilities.append({
                        "type": "Dangerous Dynamic SQL Query",
                        "line": node.lineno
                    })
        # Visits the node, continues..
        self.generic_visit(node)


    # === CFG METHODS ===

    # Checks for toctou (Time-Of-Check (To) Time-Of-Use) flaw inside the CFG
    def detect_toctou_flaws(self, cfg_info, code):
        # Split the entire source code into lines for easy indexing
        code_lines = code.splitlines()

        # Define functions typically used to check file existence or permissions
        check_calls = {
            "os.path.exists", "os.path.lexists", "os.path.isfile", "os.path.isdir", "os.path.islink",
            "os.access", "os.stat", "os.lstat", "os.path.getsize", "os.path.getmtime", "os.path.getctime",
            "os.path.samefile", "os.path.sameopenfile", "os.path.ismount", "os.scandir", "os.listdir",
            "os.readlink", "os.environ.get", "pathlib.Path.exists", "pathlib.Path.is_file",
            "pathlib.Path.is_dir", "pathlib.Path.stat"
        }

        # Define functions that operate on or modify files — the "use" phase
        use_calls = {
            "open", "os.open", "os.remove", "os.unlink", "os.rename", "os.replace", "os.rmdir", "os.removedirs",
            "os.mkdir", "os.makedirs", "shutil.copy", "shutil.copy2", "shutil.copytree", "shutil.move",
            "shutil.rmtree", "tempfile.NamedTemporaryFile", "tempfile.mkstemp", "tempfile.mkdtemp",
            "os.write", "os.chmod", "os.chown", "os.fchmod", "os.fchown", "os.truncate", "os.ftruncate",
            "os.symlink", "os.link", "os.fsync", "os.fdatasync", "json.load", "pickle.load",
            "pathlib.Path.unlink", "pathlib.Path.rename", "pathlib.Path.replace", "pathlib.Path.rmdir",
            "pathlib.Path.mkdir", "pathlib.Path.write_text", "pathlib.Path.write_bytes"
        }

        # Iterate over each function block in the control flow graph
        for func in cfg_info:
            # Extract the source code lines corresponding to this specific function
            func_code = code_lines[func.lineno - 1: func.endline]

            # Prepare two lists: one for all 'check' operations, one for all 'use' operations
            check_lines = []
            use_lines = []

            # Go through each line in the function and classify it
            for line in func_code:
                # If the line contains any check function, store it
                if any(check_call in line for check_call in check_calls):
                    check_lines.append(line)
                # If the line contains any use function, store it
                if any(use_call in line for use_call in use_calls):
                    use_lines.append(line)

            # For each combination of check and use lines,
            # we want to verify if they act on the same variable/resource
            for check_line in check_lines:
                for use_line in use_lines:
                    # Extract all identifiers (e.g., variable names) used in the lines
                    check_vars = self.extract_identifiers(check_line)
                    use_vars = self.extract_identifiers(use_line)

                    # If there is any overlap (same variable used in both), we have a potential TOCTOU
                    if check_vars & use_vars:
                        self.vulnerabilities.append({
                            "type": "Potential TOCTOU vulnerability",
                            "check": check_line.strip(),
                            "use": use_line.strip(),
                            "function": func.name,
                            "check_line": func.lineno + func_code.index(check_line),
                            "use_line": func.lineno + func_code.index(use_line),
                            "complexity": func.complexity
                        })



    # === ORCHESTRATOR ===

    # This is the orchestrator method that starts the full analysis (visit of AST tree + CFG)
    def analyze(self, code: str) -> List[Dict[str, Any]]:
        # AST Check
        try:
            # Parse the input Python code into an Abstract Syntax Tree (AST)
            tree = ast.parse(code)

            # Start visiting the AST nodes using the visitor pattern
            self.visit(tree)

        except SyntaxError as e:
            # If the code is not valid Python syntax, return the syntax error information
            return [{"error": f"Syntax error at line {e.lineno}: {e.text}"}]

        # CFG Check
        # Build a Control Flow Graph (CFG) using an external visitor (cc_visit)
        cfg_info = cc_visit(code)

        # Run TOCTOU (Time-Of-Check to Time-Of-Use) vulnerability detection on the CFG
        self.detect_toctou_flaws(cfg_info, code)

        # Results
        # Return the list of detected vulnerabilities, if any
        return self.vulnerabilities


    # === TOOLS ===

    # Tool used with an AST func as argument to get back the full name of it
    def get_full_func_name(self, func) -> str:
        # If the function is a simple name (e.g., eval, print), return its identifier
        if isinstance(func, ast.Name):
            return func.id
        # If the function is a method of a named object (e.g., subprocess.call),
        # return it in the format "object.function"
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}"
        # In all other cases (e.g., nested attributes or complex expressions), return an empty string
        return ""


    def is_tainted_expr(self, expr):
        if isinstance(expr, ast.Name):
            return expr.id in self.tainted_vars
        elif isinstance(expr, ast.BinOp):
            return self.is_tainted_expr(expr.left) or self.is_tainted_expr(expr.right)
        elif isinstance(expr, ast.Call):
            if isinstance(expr.func, ast.Name):
                return expr.func.id in self.vulnerable_sources
        elif isinstance(expr, ast.JoinedStr):
            return any(self.is_tainted_expr(value) for value in expr.values)
        return False

    def extract_identifiers(self, line: str) -> set:
        """
        Extracts all Python-like identifiers (variable names, object names) from a line of code.
        This is a basic approximation and does not parse the AST.
        """
        import re
        return set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", line))



