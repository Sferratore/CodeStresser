import unittest
import tempfile
import shutil
import os
from pathlib import Path
from prod.CodeReader import CodeReader

class TestCodeReader(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def create_file(self, relative_path, content, encoding='utf-8'):
        file_path = os.path.join(self.test_dir, relative_path)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w", encoding=encoding) as f:
            f.write(content)
        return file_path

    def test_read_single_py_file(self):
        file_path = self.create_file("test.py", "print('Hello')")
        reader = CodeReader()
        results = reader.read_files(file_path)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], file_path)
        self.assertEqual(results[0][1], "print('Hello')")

    def test_ignore_non_py_extension(self):
        file_path = self.create_file("note.txt", "ignored")
        reader = CodeReader()
        results = reader.read_files(file_path)
        self.assertEqual(len(results), 0)

    def test_read_directory_with_multiple_py_files(self):
        file1 = self.create_file("a.py", "print(1)")
        file2 = self.create_file("subdir/b.py", "print(2)")
        reader = CodeReader()
        results = reader.read_files(self.test_dir)
        paths = [r[0] for r in results]
        self.assertIn(file1, paths)
        self.assertIn(file2, paths)
        self.assertEqual(len(results), 2)

    def test_mixed_file_extensions_in_directory(self):
        self.create_file("a.py", "print(1)")
        self.create_file("b.txt", "ignored")
        reader = CodeReader()
        results = reader.read_files(self.test_dir)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0][0].endswith("a.py"))

    def test_iso_8859_file(self):
        file_path = self.create_file("latin.py", "print('Caffè')", encoding="ISO-8859-1")
        reader = CodeReader()
        results = reader.read_files(file_path)
        self.assertEqual(len(results), 1)
        self.assertIn("Caffè", results[0][1])

    def test_invalid_path(self):
        invalid_path = os.path.join(self.test_dir, "does_not_exist.py")
        reader = CodeReader()
        results = reader.read_files(invalid_path)
        self.assertEqual(results, [])

if __name__ == '__main__':
    unittest.main()
