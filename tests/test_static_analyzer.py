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
        self.assertEqual(len(results), 4)
        self.assertEqual(results[0]['type'], 'Generally Dangerous Function Call')
        self.assertEqual(results[0]['line'], 3)
        self.assertEqual(results[1]['type'], 'Dangerous Function Call: Critical Sink Needing Try')
        self.assertEqual(results[1]['line'], 3)
        self.assertEqual(results[2]['type'], 'Dangerous Function Call: Tainted Parameter Source')
        self.assertEqual(results[2]['line'], 3)

    def test_nesting_depth(self):
        code = "def deep():\n  if True:\n    if True:\n      if True:\n        if True:\n          pass"
        results = self.analyze(code)
        self.assertEqual(results[0]['type'], 'Excessive Control Structure Nesting')
        self.assertEqual(results[0]['line'], 1)

    def test_clean_code(self):
        code = "def safe():\n  try:\n    print('ok')\n  except: pass"
        results = self.analyze(code)
        self.assertEqual(len(results), 0)

    def test_feature_vector_output(self):
        code = "def f():\n eval(input())"
        vulns = self.analyze(code)
        vector = generate_feature_vector(vulns)
        self.assertEqual(vector['generally_dangerous_calls'], 1)
        self.assertEqual(vector['unprotected_critical_calls'], 1)
        self.assertEqual(vector['tainted_input_in_dangerous_calls'], 1)

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
        results = self.analyze(code)

        self.assertEqual(len(results), 7)

        self.assertEqual(results[0]['type'], 'Generally Dangerous Function Call')
        self.assertEqual(results[0]['function'], 'eval')
        self.assertEqual(results[0]['line'], 4)

        self.assertEqual(results[1]['type'], 'Dangerous Function Call: Critical Sink Needing Try')
        self.assertEqual(results[1]['function'], 'eval')
        self.assertEqual(results[1]['line'], 4)

        self.assertEqual(results[2]['type'], 'Dangerous Function Call: Tainted Parameter Source')
        self.assertEqual(results[2]['sink'], 'eval')
        self.assertEqual(results[2]['line'], 4)

        self.assertEqual(results[3]['type'], 'Generally Dangerous Function Call')
        self.assertEqual(results[3]['function'], 'cursor.execute')
        self.assertEqual(results[3]['line'], 7) #because \n line does not get counted

        self.assertEqual(results[4]['type'], 'Dangerous Function Call: Critical Sink Needing Try')
        self.assertEqual(results[4]['function'], 'cursor.execute')
        self.assertEqual(results[4]['line'], 7)

        self.assertEqual(results[5]['type'], 'Dangerous Function Call: Tainted Parameter Source')
        self.assertEqual(results[5]['sink'], 'cursor.execute')
        self.assertEqual(results[5]['line'], 7)

        self.assertEqual(results[6]['type'], 'Dangerous Dynamic SQL Query')
        self.assertEqual(results[6]['line'], 7)

    def test_unprotected_dangerous_call_not_mitigated_by_try(self):
        code = """
    def f():
        try:
            print("not dangerous")
        except:
            pass
        eval(input())  # should be detected as unprotected
    """
        results = self.analyze(code)
        types = [v['type'] for v in results]
        self.assertIn("Dangerous Function Call: Critical Sink Needing Try", types)
        self.assertIn("Dangerous Function Call: Tainted Parameter Source", types)
        self.assertIn("Generally Dangerous Function Call", types)

    def test_indirect_tainted_var(self):
        code = """
    query = "SELECT * FROM users WHERE name = '" + input() + "'" 
    cursor.execute(query)
    """
        results = self.analyze(code)
        types = [v['type'] for v in results]
        self.assertIn("Dangerous Dynamic SQL Query", types)
        self.assertIn("Dangerous Function Call: Tainted Parameter Source", types)
        self.assertIn("Generally Dangerous Function Call", types)
        self.assertIn("Dangerous Function Call: Critical Sink Needing Try", types)

if __name__ == '__main__':
    unittest.main()
