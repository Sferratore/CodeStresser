import unittest
from prod.StaticAnalyzer import StaticAnalyzer, generate_feature_vector

class TestStaticAnalyzer(unittest.TestCase):

    def analyze(self, code):
        analyzer = StaticAnalyzer()
        return analyzer.analyze(code)

    def test_eval_detection(self):
        code = "eval(input())"
        results = self.analyze(code)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]['type'], 'Generally Dangerous Function Call')
        self.assertEqual(results[0]['line'], 1)
        self.assertEqual(results[1]['type'], 'Dangerous Function Call: Critical Sink Needing Try')
        self.assertEqual(results[1]['line'], 1)
        self.assertEqual(results[2]['type'], 'Dangerous Function Call: Tainted Parameter Source')
        self.assertEqual(results[2]['line'], 1)

    def test_sql_injection_detection(self):
        code = """
name = input()
cursor.execute('SELECT * FROM users WHERE name = ' + name)
        """
        results = self.analyze(code)
        self.assertEqual(len(results), 4)
        self.assertEqual(results[0]['type'], 'Generally Dangerous Function Call')
        self.assertEqual(results[0]['line'], 3)
        self.assertEqual(results[1]['type'], 'Dangerous Function Call: Critical Sink Needing Try')
        self.assertEqual(results[1]['line'], 3)
        self.assertEqual(results[2]['type'], 'Dangerous Function Call: Tainted Parameter Source')
        self.assertEqual(results[2]['line'], 3)
        self.assertEqual(results[3]['type'], 'Dangerous Dynamic SQL Query')
        self.assertEqual(results[3]['line'], 3)

    def test_taint_flow(self):
        code = """
user = input()
os.system(user)
"""
        results = self.analyze(code)
        self.assertTrue(any(v.get('type') == 'Tainted Data Flow to Dangerous Sink' for v in results))

    def test_nesting_depth(self):
        code = "def deep():\n  if True:\n    if True:\n      if True:\n        if True:\n          pass"
        results = self.analyze(code)
        self.assertTrue(any(v['type'] == 'Excessive Control Structure Nesting' for v in results))

    def test_clean_code(self):
        code = "def safe():\n  try:\n    print('ok')\n  except: pass"
        results = self.analyze(code)
        self.assertEqual(len(results), 0)

    def test_feature_vector_output(self):
        code = "def f():\n eval(input())"
        analyzer = StaticAnalyzer()
        vulns = analyzer.analyze(code)
        vector = generate_feature_vector(vulns)
        self.assertEqual(vector['dangerous_function_calls'], 1)
        self.assertEqual(vector['missing_error_handling'], 1)

    def test_vulnerable_code(self):
        code = """
def unsafe():
    user_input = input()
    eval(user_input)

def sql_example():
    query = "SELECT * FROM users WHERE name = '" + input() + "'" 
    cursor.execute(query)

def safe():
    try:
        eval("2+2")
    except:
        print("Error")
"""
        analyzer = StaticAnalyzer()
        vulnerabilities = analyzer.analyze(code)

        vuln_types = [v["type"] for v in vulnerabilities]

        self.assertIn("Unprotected Critical Function Call", vuln_types)
        self.assertIn("Tainted Data Flow to Dangerous Sink", vuln_types)
        self.assertIn("Dangerous Function Call", vuln_types)
        self.assertIn("Dynamic SQL Query", vuln_types)

        self.assertNotIn({'type': 'Unprotected Critical Function Call', 'function': 'eval', 'line': 11},
                             vulnerabilities)

    def test_unprotected_dangerous_call_not_mitigated_by_try(self):
        code = """
            def f():
                try:
                    print("not dangerous")
                except:
                    pass
                eval(input())  # should be detected as unprotected
        """
        analyzer = StaticAnalyzer()
        results = analyzer.analyze(code)

        # Check that eval is flagged as unprotected (since try block doesn't protect it)
        self.assertTrue(any(
            v['type'] == 'Unprotected Critical Function Call' and v['function'] == 'eval'
            for v in results))

    def test_indirect_tainted_var(self):
        code = """
query = "SELECT * FROM users WHERE name = '" + input() + "'" 
cursor.execute(query)
"""
        analyzer = StaticAnalyzer()
        vulnerabilities = analyzer.analyze(code)

        vuln_types = [v["type"] for v in vulnerabilities]
        self.assertIn("Dynamic SQL Query", vuln_types)

if __name__ == '__main__':
    unittest.main()
