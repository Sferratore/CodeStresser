from pathlib import Path
from typing import List, Tuple

class CodeReader:
    def __init__(self, extensions: List[str] = [".py"]):
        self.extensions = extensions

    def read_files(self, path: str) -> List[Tuple[str, str]]:
        """
        Reads all the files with specified extension in a directory/single file.

        :param path: Path of file/directory.
        :return: Tuple list (file_path, content).
        """
        files_content = []

        p = Path(path)
        if p.is_file() and p.suffix in self.extensions:
            content = self._read_file(p)
            files_content.append((str(p), content))
        elif p.is_dir():
            for file_path in p.rglob("*"):
                if file_path.suffix in self.extensions:
                    content = self._read_file(file_path)
                    files_content.append((str(file_path), content))
        else:
            print(f"Path not valid or wrong extension: {path}")

        return files_content

    def _read_file(self, file_path: Path) -> str:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
        except UnicodeDecodeError:
            with open(file_path, "r", encoding="ISO-8859-1") as f:
                return f.read()
