# core/infrastructure/adapter/scanner_adapter.py
from abc import ABC, abstractmethod # Aunque no se usan directamente como interfaces base aquí, las mantengo si son parte de tu estructura.
from typing import List, Dict, Optional

# Importaciones de las entidades de dominio
# DnsRecord no se usa directamente en este archivo, pero no causa error.
from core.domain.entities import GoogleDorkResult, DnsRecord, WhoisInfo, NmapHost

# Importaciones de las clases Scanner de sus respectivos módulos
from ..scanner.google_dorks import GoogleDorkScanner
from ..scanner.dns_scan import DNSScanner
# Asegúrate de que estas rutas de importación y los nombres de las clases sean correctos
# según la ubicación y definición de tus archivos de scanner.
from ..scanner.whois_scan import WhoisScanner   # <--- DESCOMENTADO
from ..scanner.nmap_scan import NmapScanner     # <--- DESCOMENTADO

# Ya no necesitamos las clases Placeholder si vamos a usar las implementaciones reales.
# class WhoisScannerPlaceholder: ...
# class NmapScannerPlaceholder: ...


class GoogleDorkScannerAdapter:
    def __init__(self, api_key: str, search_engine_id: str):
        self.scanner = GoogleDorkScanner(api_key=api_key, search_engine_id=search_engine_id)

    def search(self, query: str, start: int = 1, lang: str = "lang_es") -> Optional[List[GoogleDorkResult]]:
        return self.scanner.search(query, start, lang)

class DnsScannerAdapter:
    def __init__(self):
        self.scanner = DNSScanner()

    def resolve(self, domain: str, record_types: Optional[List[str]] = None) -> Dict[str, List[str]]:
        return self.scanner.resolve_records_raw(domain, record_types)

class WhoisScannerAdapter:
    def __init__(self):
        # Usando la implementación real de WhoisScanner
        self.scanner = WhoisScanner() # <--- MODIFICADO

    def get_info(self, domain: str) -> WhoisInfo:
        # Asume que tu clase WhoisScanner real tiene un método get_whois_info_raw
        return self.scanner.get_whois_info_raw(domain)

class NmapScannerAdapter:
    def __init__(self):
        # Usando la implementación real de NmapScanner
        self.scanner = NmapScanner() # <--- MODIFICADO

    def scan(self, targets: List[str]) -> List[NmapHost]:
        # Asume que tu clase NmapScanner real tiene un método scan_targets_raw
        return self.scanner.scan_targets_raw(targets)