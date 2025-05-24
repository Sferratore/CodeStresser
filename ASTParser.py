import ast
from typing import Tuple, Optional

class ASTParser:
    def parse(self, file_path: str, code: str) -> Tuple[str, Optional[ast.AST]]:
        """
        Fa parsing del codice sorgente in un AST.

        :param file_path: Percorso del file (per tracciabilità).
        :param code: Contenuto del codice sorgente.
        :return: Tupla (file_path, AST o None in caso di errore).
        """
        try:
            tree = ast.parse(code, filename=file_path)
            return file_path, tree
        except SyntaxError as e:
            print(f"Errore di sintassi nel file {file_path}: {e}")
            return file_path, None