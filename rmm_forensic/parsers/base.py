"""Clase base abstracta para todos los parsers de RMM."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import ClassVar

from ..models.base import ParseResult, RMMType


class BaseParser(ABC):
    """
    Interfaz abstracta que todos los parsers de RMM deben implementar.

    Cada parser:
    - Identifica si puede parsear un archivo (can_parse)
    - Parsea el archivo y devuelve un ParseResult normalizado
    - Declara patrones de archivo y rutas conocidas para el discovery engine
    """

    rmm_type: ClassVar[RMMType]

    @abstractmethod
    def can_parse(self, filepath: str) -> bool:
        """
        Retorna True si este parser puede manejar el archivo dado.
        Verifica nombre de archivo y/o firmas de contenido.
        """
        ...

    @abstractmethod
    def parse(self, filepath: str, hostname: str = "") -> ParseResult:
        """
        Parsea el archivo y retorna un ParseResult normalizado.

        Args:
            filepath: Ruta al archivo de log
            hostname: Hostname del equipo de donde proviene el log (si se conoce)
        """
        ...

    @classmethod
    def file_patterns(cls) -> list[str]:
        """
        Patrones glob para archivos que este parser maneja.
        Usados por el discovery engine para búsqueda por nombre.
        Ejemplo: ["ad.trace", "ad_svc.trace", "connection_trace.txt"]
        """
        return []

    @classmethod
    def known_paths_windows(cls) -> list[str]:
        """Rutas conocidas de instalación en Windows (con variables de entorno)."""
        return []

    @classmethod
    def known_paths_linux(cls) -> list[str]:
        """Rutas conocidas de instalación en Linux."""
        return []

    @classmethod
    def known_paths_macos(cls) -> list[str]:
        """Rutas conocidas de instalación en macOS."""
        return []

    @classmethod
    def content_signatures(cls) -> list[str]:
        """
        Patrones regex que identifican el contenido de logs de este RMM.
        Se aplican a las primeras líneas del archivo para identificación rápida.
        """
        return []
