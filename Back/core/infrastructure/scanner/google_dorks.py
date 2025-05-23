#security_apy/core/infrastructure/scanner/google_dorks.py
import requests
import logging
from typing import List, Dict, Optional
from core.domain.entities import GoogleDorkResult
from dotenv import load_dotenv
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_env_variables() -> Optional[Dict[str, str]]:
    load_dotenv()
    api_key = os.getenv('API_KEY_SEARCH_GOOGLE')
    search_engine_id = os.getenv('SEARCH_ENGINE_ID')

    if not api_key or not search_engine_id:
        logging.error("API Key o Search Engine ID no encontrados en el archivo .env")
        return None
    logging.info("API Key y Search Engine ID cargados correctamente.")
    return {
        'api_key': api_key,
        'search_engine_id': search_engine_id
    }

def perform_google_search_raw(api_key: str, search_engine_id: str, query: str, start: int = 1, lang: str = "lang_es") -> Optional[List[Dict]]:
    base_url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": api_key,
        "cx": search_engine_id,
        "q": query,
        "start": start,
        "lr": lang
    }
    try:
        response = requests.get(base_url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get('items', [])
    except requests.exceptions.RequestException as e:
        logging.error(f"Error al realizar la búsqueda en Google: {e}")
        return None

def map_google_results(raw_results: Optional[List[Dict]]) -> Optional[List[GoogleDorkResult]]:
    if not raw_results:
        return None
    results = []
    for item in raw_results:
        results.append(GoogleDorkResult(
            title=item.get('title', ''),
            link=item.get('link', ''),
            snippet=item.get('snippet', '')
        ))
    return results

class GoogleDorkScanner:
    def __init__(self, api_key: str, search_engine_id: str):
        self.api_key = api_key
        self.search_engine_id = search_engine_id

    def search(self, query: str, start: int = 1, lang: str = "lang_es") -> Optional[List[GoogleDorkResult]]:
        raw_results = perform_google_search_raw(self.api_key, self.search_engine_id, query, start, lang)
        return map_google_results(raw_results)