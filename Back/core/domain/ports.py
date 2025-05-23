# core/domain/ports.py
from abc import ABC, abstractmethod
from typing import List, Dict, Optional

class GoogleDorkResultItem(Dict):
    """
    Representa un solo ítem de resultado de Google Dork.
    Hereda de dict para facilitar la serialización, pero puedes definir campos explícitos.
    """
    title: Optional[str]
    link: Optional[str]
    snippet: Optional[str]

class GoogleDorkSearchPort(ABC):
    """
    Puerto para el servicio de búsqueda de Google Dorks.
    Define el contrato que deben seguir las implementaciones de búsqueda.
    """
    @abstractmethod
    def search(self, query: str, start: int = 1, lang: str = "lang_es") -> Optional[List[GoogleDorkResultItem]]:
        """
        Realiza una búsqueda de Google Dorks.

        Args:
            query: La consulta de búsqueda (dork).
            start: El índice del primer resultado a devolver (para paginación).
            lang: El código de idioma para la búsqueda.

        Returns:
            Una lista de diccionarios representando los resultados, o None si hay un error.
        """
        pass
