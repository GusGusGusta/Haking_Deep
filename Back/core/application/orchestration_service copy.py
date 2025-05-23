# core/application/orchestration_service.py
import os
import logging
from typing import Dict, Any, List, Optional

from core.infrastructure.scanner.dns_scan import DNSScanner
from core.infrastructure.scanner.google_dorks import GoogleDorkScanner, load_env_variables as load_google_env_vars
from core.infrastructure.scanner.nmap_scan import NmapScanner
from core.infrastructure.scanner.whois_scan import WhoisScanner
from chat.services.deep_seek_service import consultar_deepseek
from core.domain.entities import GoogleDorkResult, NmapHost, WhoisInfo

logger = logging.getLogger(__name__)

# --- Funciones de Formateo (sin cambios respecto a la última versión que te di) ---
def format_dns_results_structured(dns_data: Dict[str, List[str]]) -> Dict:
    if not dns_data:
        return {"error": "No se obtuvieron resultados DNS.", "details": {}}
    return {"details": dns_data}

def format_dns_results_string(dns_data: Dict[str, List[str]]) -> str:
    if not dns_data:
        return "No se obtuvieron resultados DNS.\n"
    formatted_output = "--- Resultados del Escaneo DNS ---\n"
    for record_type, records in dns_data.items():
        if records:
            formatted_output += f"{record_type}:\n"
            for record in records:
                formatted_output += f"  - {record}\n"
        else:
            formatted_output += f"{record_type}: (No se encontraron registros)\n"
    formatted_output += "\n"
    return formatted_output

def format_nmap_results_structured(nmap_hosts: List[NmapHost]) -> List[Dict]:
    return [host.model_dump() if hasattr(host, 'model_dump') else host.dict() for host in nmap_hosts]

def format_nmap_results_string(nmap_hosts: List[NmapHost], target_for_nmap: str) -> str:
    if not nmap_hosts:
        return f"No se obtuvieron resultados Nmap para {target_for_nmap} o el host está caído/filtrado.\n"
    formatted_output = "--- Resultados del Escaneo Nmap ---\n"
    for host in nmap_hosts:
        formatted_output += f"Objetivo: {host.ip}\n"
        status_display = host.status if host.status is not None else "desconocido"
        formatted_output += f"Estado: {status_display}\n"
        if host.error:
            formatted_output += f"Error Nmap: {host.error}\n"
        if host.ports:
            formatted_output += "Puertos:\n"
            for port_info in host.ports:
                service_details = ""
                if port_info.service:
                    service_parts = [
                        port_info.service.get('name', ''),
                        port_info.service.get('product', ''),
                        port_info.service.get('version', ''),
                        port_info.service.get('extrainfo', '')
                    ]
                    service_details = " ".join(filter(None, service_parts))
                formatted_output += f"  - Puerto: {port_info.port}/{port_info.protocol}\n"
                formatted_output += f"    Estado: {port_info.state}\n"
                if service_details:
                    formatted_output += f"    Servicio: {service_details}\n"
        else:
            formatted_output += "Puertos: (No se encontraron puertos abiertos o información de puertos no disponible)\n"
        formatted_output += "\n"
    return formatted_output

def format_whois_results_structured(whois_data: Optional[WhoisInfo]) -> Optional[Dict]:
    return whois_data.to_dict() if whois_data and hasattr(whois_data, 'to_dict') else None

def format_whois_results_string(whois_data: Optional[WhoisInfo], domain_target: str) -> str:
    if not whois_data or whois_data.error:
        error_msg = whois_data.error if whois_data and whois_data.error else "No se pudo obtener información."
        return f"--- Resultados del Escaneo Whois para {domain_target} ---\nError: {error_msg}\n\n"
    
    formatted_output = f"--- Resultados del Escaneo Whois para {domain_target} ---\n"
    # ... (resto de los campos de formateo de Whois como en la versión anterior) ...
    if whois_data.domain_name:
        formatted_output += f"Nombre de Dominio: {', '.join(whois_data.domain_name)}\n"
    if whois_data.registrar:
        formatted_output += f"Registrador: {whois_data.registrar}\n"
    if whois_data.creation_date:
        formatted_output += f"Fecha de Creación: {whois_data.creation_date}\n"
    if whois_data.expiration_date:
        formatted_output += f"Fecha de Expiración: {whois_data.expiration_date}\n"
    if whois_data.updated_date:
        formatted_output += f"Última Actualización: {whois_data.updated_date}\n"
    if whois_data.name_servers:
        formatted_output += f"Servidores de Nombre: {', '.join(whois_data.name_servers)}\n"
    if whois_data.status:
        formatted_output += f"Estado: {', '.join(whois_data.status)}\n"
    if whois_data.emails:
        formatted_output += f"Emails: {', '.join(whois_data.emails)}\n"
    if whois_data.country:
        formatted_output += f"País: {whois_data.country}\n"
    formatted_output += "\n"
    return formatted_output


def format_google_dorks_results_structured(dork_results: Optional[List[GoogleDorkResult]]) -> Optional[List[Dict]]:
    return [result.to_dict() for result in dork_results] if dork_results else None

def format_google_dorks_results_string(dork_results: Optional[List[GoogleDorkResult]], query_used: str) -> str:
    if dork_results is None:
        return f"--- Resultados de Google Dorks (Query: {query_used}) ---\nError al realizar la búsqueda.\n\n"
    if not dork_results:
         return f"--- Resultados de Google Dorks (Query: {query_used}) ---\nNo se encontraron ítems para esta consulta.\n\n"
    # ... (resto del código de formateo de Google Dorks como en la versión anterior) ...
    formatted_output = f"--- Resultados de Google Dorks (Query: {query_used}) ---\n"
    for item in dork_results:
        formatted_output += f"Título: {item.title}\n"
        formatted_output += f"Enlace: {item.link}\n"
        formatted_output += f"Fragmento: {item.snippet}\n---\n"
    formatted_output += "\n"
    return formatted_output


class OrchestrationService:
    def __init__(self):
        google_env = load_google_env_vars()
        self.google_api_key = google_env.get('api_key')
        self.Google_Search_engine_id = google_env.get('search_engine_id')

        self.dns_scanner = DNSScanner()
        self.nmap_scanner = NmapScanner()
        self.whois_scanner = WhoisScanner()

        if self.google_api_key and self.Google_Search_engine_id:
            self.google_dork_scanner = GoogleDorkScanner(
                api_key=self.google_api_key,
                search_engine_id=self.Google_Search_engine_id
            )
        else:
            self.google_dork_scanner = None
            logger.warning("API Key o Search Engine ID de Google no cargados. Google Dorks no estará disponible.")
        
        self.deepseek_api_key = os.getenv('DEEPSEEK_API_KEY')
        if not self.deepseek_api_key:
            logger.warning("DEEPSEEK_API_KEY no encontrada en las variables de entorno.")

    # CAMBIO: 'target' renombrado a 'url_dominio'
    def run_scan(self, url_dominio: str, scenario: str, custom_gquery: Optional[str] = None) -> Dict[str, Any]:
        logger.info(f"Servicio de orquestación: Iniciando escaneo para {url_dominio}, escenario: {scenario.lower()}")
        
        current_scenario = scenario.lower() # Normalizar a minúsculas

        results_structured = {"dns": None, "nmap": None, "whois": None, "google_dorks": None}
        results_string_formatted = {"dns": "", "nmap": "", "whois": "", "google_dorks": ""}
        execution_errors = [] 

        # 1. DNS Scan (se ejecuta en ambos escenarios)
        try:
            logger.info(f"Ejecutando escaneo DNS para {url_dominio}...")
            raw_dns = self.dns_scanner.resolve_records_raw(url_dominio)
            results_structured["dns"] = format_dns_results_structured(raw_dns)
            results_string_formatted["dns"] = format_dns_results_string(raw_dns)
        except Exception as e:
            logger.error(f"Error en DNS Scan para {url_dominio}: {e}", exc_info=True)
            execution_errors.append(f"DNS Scan: {str(e)}")
            results_string_formatted["dns"] = f"--- Resultados del Escaneo DNS ---\nError: {e}\n\n"
            results_structured["dns"] = {"error": str(e), "details": {}}

        # 2. Nmap Scan (se ejecuta en ambos escenarios según tu nueva lógica)
        try:
            logger.info(f"Ejecutando escaneo Nmap para {url_dominio}...")
            raw_nmap = self.nmap_scanner.scan_targets_raw([url_dominio]) # Nmap toma una lista
            results_structured["nmap"] = format_nmap_results_structured(raw_nmap)
            results_string_formatted["nmap"] = format_nmap_results_string(raw_nmap, url_dominio)
        except FileNotFoundError:
            logger.error("Error Nmap: Nmap no está instalado o no se encuentra en el PATH.")
            execution_errors.append("Nmap: Nmap no está instalado o no se encuentra en el PATH.")
            results_string_formatted["nmap"] = "--- Resultados del Escaneo Nmap ---\nError: Nmap no está instalado.\n\n"
            results_structured["nmap"] = [{"error": "Nmap no instalado"}] # Nmap devuelve una lista de hosts
        except Exception as e:
            logger.error(f"Error en Nmap Scan para {url_dominio}: {e}", exc_info=True)
            execution_errors.append(f"Nmap Scan: {str(e)}")
            results_string_formatted["nmap"] = f"--- Resultados del Escaneo Nmap ---\nError: {e}\n\n"
            results_structured["nmap"] = [{"error": str(e)}]
            
        # 3. Whois Scan (se ejecuta en ambos escenarios)
        try:
            logger.info(f"Ejecutando escaneo Whois para {url_dominio}...")
            raw_whois = self.whois_scanner.get_whois_info_raw(url_dominio)
            results_structured["whois"] = format_whois_results_structured(raw_whois)
            results_string_formatted["whois"] = format_whois_results_string(raw_whois, url_dominio)
        except Exception as e:
            logger.error(f"Error en Whois Scan para {url_dominio}: {e}", exc_info=True)
            execution_errors.append(f"Whois Scan: {str(e)}")
            results_string_formatted["whois"] = f"--- Resultados del Escaneo Whois para {url_dominio} ---\nError: {e}\n\n"
            results_structured["whois"] = {"error": str(e)}

        # 4. Google Dorks Scan (solo para escenario "complete" o "full")
        if current_scenario in ["complete", "full"]:
            if self.google_dork_scanner:
                logger.info(f"Ejecutando escaneo Google Dorks para {url_dominio}...")
                google_query_executed = custom_gquery if custom_gquery else f'site:{url_dominio} filetype:log OR "Index of /" OR "admin" OR "login"'
                try:
                    raw_google = self.google_dork_scanner.search(query=google_query_executed)
                    results_structured["google_dorks"] = {
                        "query_executed": google_query_executed,
                        "results": format_google_dorks_results_structured(raw_google)
                    }
                    results_string_formatted["google_dorks"] = format_google_dorks_results_string(raw_google, google_query_executed)
                except Exception as e:
                    logger.error(f"Error en Google Dorks Scan para {url_dominio} con query '{google_query_executed}': {e}", exc_info=True)
                    execution_errors.append(f"Google Dorks Scan: {str(e)}")
                    results_string_formatted["google_dorks"] = f"--- Resultados de Google Dorks (Query: {google_query_executed}) ---\nError: {e}\n\n"
                    results_structured["google_dorks"] = {"query_executed": google_query_executed, "error": str(e)}
            else:
                msg = "Google Dorks omitido: configuración de API no disponible."
                logger.warning(msg)
                execution_errors.append(msg)
                results_string_formatted["google_dorks"] = f"--- Resultados de Google Dorks ---\n{msg}\n\n"
                results_structured["google_dorks"] = {"query_executed": "", "error": msg, "results": []}
        else: # Escenario "basic" omite Google Dorks
            logger.info(f"Google Dorks omitido para escenario '{current_scenario}'.")
            results_string_formatted["google_dorks"] = f"Google Dorks omitido para escenario '{current_scenario}'.\n"
            results_structured["google_dorks"] = {"status": "omitted", "reason": f"Scenario: {current_scenario}", "results": []}
        
        # 5. Compilar prompt para DeepSeek
        deepseek_prompt_parts = [f"Análisis de Seguridad para el objetivo: {url_dominio}\n"]
        if results_string_formatted["dns"]: deepseek_prompt_parts.append(results_string_formatted["dns"])
        if results_string_formatted["nmap"]: deepseek_prompt_parts.append(results_string_formatted["nmap"])
        if results_string_formatted["whois"]: deepseek_prompt_parts.append(results_string_formatted["whois"])
        if current_scenario in ["complete", "full"] and results_string_formatted["google_dorks"]: # Solo incluye si se ejecutó
            deepseek_prompt_parts.append(results_string_formatted["google_dorks"])
        
        deepseek_prompt_parts.append(
            "Por favor, analiza la información de seguridad recopilada para el objetivo. "
            "Proporciona un resumen de los hallazgos clave, identifica posibles vulnerabilidades "
            "o áreas de preocupación relevantes para la seguridad, y sugiere recomendaciones "
            "generales de seguridad basadas estrictamente en los datos provistos. "
            "Responde en español."
        )
        deepseek_prompt = "\n".join(filter(None, deepseek_prompt_parts))

        # 6. Consultar DeepSeek
        deepseek_analysis = "Análisis de DeepSeek no ejecutado o fallido."
        if self.deepseek_api_key:
            try:
                logger.info(f"Enviando datos a DeepSeek para análisis del objetivo {url_dominio}...")
                deepseek_analysis = consultar_deepseek(deepseek_prompt)
            except Exception as e:
                logger.error(f"Error al consultar DeepSeek para {url_dominio}: {e}", exc_info=True)
                execution_errors.append(f"DeepSeek API: {str(e)}")
                deepseek_analysis = f"Error al contactar o procesar la respuesta de DeepSeek: {str(e)}"
        else:
            logger.warning(f"No se consultará DeepSeek para {url_dominio} porque DEEPSEEK_API_KEY no está configurada.")
            execution_errors.append("DeepSeek API: Clave no configurada.")

        return {
            "url_dominio": url_dominio, # CAMBIADO de "target"
            "scenario": current_scenario,
            "scan_results": results_structured,
            "deepseek_analysis": deepseek_analysis,
            "execution_errors": execution_errors
        }