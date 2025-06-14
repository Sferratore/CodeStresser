import unittest
import ast
from prod.StaticAnalyzer import StaticAnalyzer

class TestCFGGenerator(unittest.TestCase):
    def setUp(self):
        self.analyzer = StaticAnalyzer()

    def build_edges(self, code):
        tree = ast.parse(code)
        return self.analyzer.build_cfg(tree)

    def test_linear_flow(self):
        code = """
def foo():
    a = 1
    b = 2
    return a
"""
        edges = self.build_edges(code)
        self.assertIn(3, edges.get(2, set()))
        self.assertIn(4, edges.get(3, set()))
        self.assertIn(5, edges.get(4, set()))

    def test_if_flow(self):
        code = """
def foo(x):
    if x:
        a = 1
    else:
        a = 2
    return a
"""
        edges = self.build_edges(code)
        self.assertIn(4, edges.get(3, set()))
        self.assertIn(6, edges.get(3, set()))
        self.assertIn(7, edges.get(4, set()))
        self.assertIn(7, edges.get(6, set()))

if __name__ == '__main__':
    unittest.main()
