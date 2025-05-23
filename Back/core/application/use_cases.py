from typing import List, Optional, Dict
from core.domain.services import GoogleDorkService, DNSService, WhoisService, NmapService
from core.domain.entities import GoogleDorkResult, WhoisInfo, NmapHost
from core.infrastructure.adapter.scanner_adapter import (
    GoogleDorkScannerAdapter,
    DnsScannerAdapter,
    WhoisScannerAdapter,
    NmapScannerAdapter
)
import os
from dotenv import load_dotenv

def load_api_keys():
    load_dotenv()
    api_key = os.getenv('API_KEY_SEARCH_GOOGLE')
    search_engine_id = os.getenv('SEARCH_ENGINE_ID')
    shodan_api_key = os.getenv("SHODAN_API_KEY") # Asegúrate de tener esta variable en .env
    return api_key, search_engine_id, shodan_api_key

class GoogleDorkUseCase:
    def execute(self, query: str) -> Optional[List[GoogleDorkResult]]:
        api_key, search_engine_id, _ = load_api_keys()
        if api_key and search_engine_id:
            adapter = GoogleDorkScannerAdapter(api_key, search_engine_id)
            service = GoogleDorkService(adapter)
            return service.perform_search(query)
        return None

class DnsScanUseCase:
    def execute(self, domain: str, record_types: Optional[List[str]] = None) -> Dict[str, List[str]]:
        adapter = DnsScannerAdapter()
        service = DNSService(adapter)
        return service.resolve_records(domain, record_types)

class WhoisScanUseCase:
    def execute(self, domain: str) -> WhoisInfo:
        adapter = WhoisScannerAdapter()
        service = WhoisService(adapter)
        return service.get_whois_info(domain)

class NmapScanUseCase:
    def execute(self, targets: List[str]) -> List[NmapHost]:
        adapter = NmapScannerAdapter()
        service = NmapService(adapter)
        return service.scan_targets(targets)