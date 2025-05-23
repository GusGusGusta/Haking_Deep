# security_api/core/domain/services.py
import logging
from typing import List, Dict, Optional
from .entities import GoogleDorkResult, DnsRecord, WhoisInfo, NmapHost

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class GoogleDorkService:
    def __init__(self, scanner_adapter):
        self.scanner_adapter = scanner_adapter

    def perform_search(self, query: str) -> Optional[List[GoogleDorkResult]]:
        return self.scanner_adapter.search(query)

class DNSService:
    def __init__(self, scanner_adapter):
        self.scanner_adapter = scanner_adapter

    def resolve_records(self, domain: str, record_types: Optional[List[str]] = None) -> Dict[str, List[str]]:
        return self.scanner_adapter.resolve(domain, record_types)

class WhoisService:
    def __init__(self, scanner_adapter):
        self.scanner_adapter = scanner_adapter

    def get_whois_info(self, domain: str) -> WhoisInfo:
        return self.scanner_adapter.get_info(domain)

class NmapService:
    def __init__(self, scanner_adapter):
        self.scanner_adapter = scanner_adapter

    def scan_targets(self, targets: List[str]) -> List[NmapHost]:
        return self.scanner_adapter.scan(targets)