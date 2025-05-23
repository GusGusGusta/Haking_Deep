# core/application/orchestration_service.py
import os
import logging
import html # Para escapar caracteres HTML en el reporte
from typing import Dict, Any, List, Optional

from core.infrastructure.scanner.dns_scan import DNSScanner
from core.infrastructure.scanner.google_dorks import GoogleDorkScanner, load_env_variables as load_google_env_vars
from core.infrastructure.scanner.nmap_scan import NmapScanner
from core.infrastructure.scanner.whois_scan import WhoisScanner
from chat.services.deep_seek_service import consultar_deepseek
from core.domain.entities import GoogleDorkResult, NmapHost, WhoisInfo, NmapPort

logger = logging.getLogger(__name__)

# --- Funciones de Formateo a String (para el prompt de DeepSeek) ---
def format_dns_results_string(dns_data: Dict[str, List[str]]) -> str:
    if not dns_data or not dns_data.get("details"): # Verifica si hay detalles
        return "No se obtuvieron resultados DNS o la estructura es inválida.\n"
    
    dns_details = dns_data["details"]
    if not isinstance(dns_details, dict) or not any(dns_details.values()): # Verifica si details es un dict y no está vacío
         return "No se encontraron registros DNS significativos.\n"

    formatted_output = "--- Resultados del Escaneo DNS ---\n"
    for record_type, records in dns_details.items():
        if records:
            formatted_output += f"{record_type}:\n"
            for record in records:
                formatted_output += f"  - {str(record)}\n" # Asegurar que sea string
        else:
            formatted_output += f"{record_type}: (No se encontraron registros)\n"
    formatted_output += "\n"
    return formatted_output

def format_nmap_results_string(nmap_hosts: List[NmapHost], target_for_nmap: str) -> str:
    if not nmap_hosts:
        return f"No se obtuvieron resultados Nmap para {target_for_nmap} o el host está caído/filtrado.\n"
    formatted_output = "--- Resultados del Escaneo Nmap ---\n"
    for host_data in nmap_hosts: # host_data es NmapHost o dict si viene de Pydantic .dict()
        host_ip = host_data.ip if isinstance(host_data, NmapHost) else host_data.get('ip', target_for_nmap)
        host_status = host_data.status if isinstance(host_data, NmapHost) else host_data.get('status', "desconocido")
        host_error = host_data.error if isinstance(host_data, NmapHost) else host_data.get('error')
        host_ports = host_data.ports if isinstance(host_data, NmapHost) else host_data.get('ports', [])

        formatted_output += f"Objetivo: {host_ip}\n"
        formatted_output += f"Estado: {host_status}\n"
        if host_error:
            formatted_output += f"Error Nmap: {host_error}\n"
        
        if host_ports:
            formatted_output += "Puertos:\n"
            for port_info_obj in host_ports: # port_info_obj es NmapPort o dict
                port_id = port_info_obj.port if isinstance(port_info_obj, NmapPort) else port_info_obj.get('port')
                port_protocol = port_info_obj.protocol if isinstance(port_info_obj, NmapPort) else port_info_obj.get('protocol')
                port_state = port_info_obj.state if isinstance(port_info_obj, NmapPort) else port_info_obj.get('state')
                port_service_dict = port_info_obj.service if isinstance(port_info_obj, NmapPort) else port_info_obj.get('service', {})
                
                service_details_str = ""
                if port_service_dict:
                    service_parts = [
                        port_service_dict.get('name', ''),
                        port_service_dict.get('product', ''),
                        port_service_dict.get('version', ''),
                        port_service_dict.get('extrainfo', '')
                    ]
                    service_details_str = " ".join(filter(None, service_parts))
                formatted_output += f"  - Puerto: {port_id}/{port_protocol}\n"
                formatted_output += f"    Estado: {port_state}\n"
                if service_details_str:
                    formatted_output += f"    Servicio: {service_details_str}\n"
        else:
            formatted_output += "Puertos: (No se encontraron puertos abiertos o información de puertos no disponible)\n"
        formatted_output += "\n"
    return formatted_output

def format_whois_results_string(whois_data_obj: Optional[WhoisInfo], domain_target: str) -> str:
    if not whois_data_obj or whois_data_obj.error:
        error_msg = whois_data_obj.error if whois_data_obj and whois_data_obj.error else "No se pudo obtener información."
        return f"--- Resultados del Escaneo Whois para {domain_target} ---\nError: {error_msg}\n\n"
    
    # Asumimos que whois_data_obj es una instancia de WhoisInfo
    formatted_output = f"--- Resultados del Escaneo Whois para {domain_target} ---\n"
    if whois_data_obj.domain_name: formatted_output += f"Nombre de Dominio: {', '.join(whois_data_obj.domain_name)}\n"
    if whois_data_obj.registrar: formatted_output += f"Registrador: {whois_data_obj.registrar}\n"
    if whois_data_obj.creation_date: formatted_output += f"Fecha de Creación: {whois_data_obj.creation_date}\n"
    if whois_data_obj.expiration_date: formatted_output += f"Fecha de Expiración: {whois_data_obj.expiration_date}\n"
    if whois_data_obj.updated_date: formatted_output += f"Última Actualización: {whois_data_obj.updated_date}\n"
    if whois_data_obj.name_servers: formatted_output += f"Servidores de Nombre: {', '.join(whois_data_obj.name_servers)}\n"
    if whois_data_obj.status: formatted_output += f"Estado: {', '.join(whois_data_obj.status)}\n"
    if whois_data_obj.emails: formatted_output += f"Emails: {', '.join(whois_data_obj.emails)}\n"
    if whois_data_obj.country: formatted_output += f"País: {whois_data_obj.country}\n"
    formatted_output += "\n"
    return formatted_output

def format_google_dorks_results_string(dork_data: Optional[Dict], query_used: str) -> str: # dork_data es el dict de "google_dorks"
    if not dork_data or dork_data.get("status") == "omitted" or dork_data.get("error"):
        error_msg = dork_data.get("error", "No ejecutado o sin resultados.")
        reason = dork_data.get("reason", "")
        status = dork_data.get("status", "")
        if status == "omitted":
            return f"--- Resultados de Google Dorks ---\nGoogle Dorks omitido para este escenario ({reason}).\n\n"
        return f"--- Resultados de Google Dorks (Query: {query_used}) ---\nError: {error_msg}\n\n"

    dork_results_list = dork_data.get("results", [])
    if not dork_results_list:
         return f"--- Resultados de Google Dorks (Query: {query_used}) ---\nNo se encontraron ítems para esta consulta.\n\n"

    formatted_output = f"--- Resultados de Google Dorks (Query: {query_used}) ---\n"
    for item_dict in dork_results_list: # item_dict es un diccionario
        formatted_output += f"Título: {item_dict.get('title','')}\nEnlace: {item_dict.get('link','')}\nFragmento: {item_dict.get('snippet','')}\n---\n"
    formatted_output += "\n"
    return formatted_output

# --- Clases y Lógica del Servicio ---
class OrchestrationService:
    def __init__(self):
        google_env = load_google_env_vars()
        self.google_api_key = google_env.get('api_key')
        # Usa el nombre de atributo que tengas funcionando (ej. Google Search_engine_id o Google Search_engine_id)
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

    def run_scan(self, url_dominio: str, scenario: str, custom_gquery: Optional[str] = None) -> Dict[str, Any]:
        logger.info(f"Servicio de orquestación: Iniciando escaneo para {url_dominio}, escenario: {scenario.lower()}")
        current_scenario = scenario.lower()

        results_structured = {"dns": None, "nmap": None, "whois": None, "google_dorks": None}
        # results_string_formatted = {"dns": "", "nmap": "", "whois": "", "google_dorks": ""}
        execution_errors = [] 

        # 1. DNS Scan
        try:
            logger.info(f"Ejecutando escaneo DNS para {url_dominio}...")
            raw_dns = self.dns_scanner.resolve_records_raw(url_dominio)
            results_structured["dns"] = {"details": raw_dns} # DNSScanner devuelve Dict[str, List[str]]
        except Exception as e:
            logger.error(f"Error en DNS Scan para {url_dominio}: {e}", exc_info=True)
            execution_errors.append(f"DNS Scan: {str(e)}")
            results_structured["dns"] = {"error": str(e), "details": {}}

        # 2. Nmap Scan
        try:
            logger.info(f"Ejecutando escaneo Nmap para {url_dominio}...")
            raw_nmap = self.nmap_scanner.scan_targets_raw([url_dominio]) # Devuelve List[NmapHost]
            results_structured["nmap"] = [host.model_dump() if hasattr(host, 'model_dump') else host.dict() for host in raw_nmap]
        except FileNotFoundError:
            msg = "Nmap: Nmap no está instalado o no se encuentra en el PATH."
            logger.error(msg); execution_errors.append(msg)
            results_structured["nmap"] = [{"error": "Nmap no instalado", "ip": url_dominio, "ports": [], "status": "error_nmap_not_found"}]
        except Exception as e:
            logger.error(f"Error en Nmap Scan para {url_dominio}: {e}", exc_info=True)
            execution_errors.append(f"Nmap Scan: {str(e)}")
            results_structured["nmap"] = [{"error": str(e), "ip": url_dominio, "ports": [], "status": "error_nmap_execution"}]
            
        # 3. Whois Scan
        try:
            logger.info(f"Ejecutando escaneo Whois para {url_dominio}...")
            raw_whois = self.whois_scanner.get_whois_info_raw(url_dominio) # Devuelve WhoisInfo
            results_structured["whois"] = raw_whois.to_dict() if raw_whois and hasattr(raw_whois, 'to_dict') else {"error": "No se pudo obtener información Whois o la estructura es inválida."}
        except Exception as e:
            logger.error(f"Error en Whois Scan para {url_dominio}: {e}", exc_info=True)
            execution_errors.append(f"Whois Scan: {str(e)}")
            results_structured["whois"] = {"error": str(e)}

        # 4. Google Dorks Scan
        google_query_executed = ""
        if current_scenario in ["complete", "full"]:
            if self.google_dork_scanner:
                logger.info(f"Ejecutando escaneo Google Dorks para {url_dominio}...")
                google_query_executed = custom_gquery if custom_gquery else f'site:{url_dominio} filetype:log OR "Index of /" OR "admin" OR "login"'
                try:
                    raw_google_results_list = self.google_dork_scanner.search(query=google_query_executed) # Devuelve List[GoogleDorkResult]
                    results_structured["google_dorks"] = {
                        "query_executed": google_query_executed,
                        "results": [res.to_dict() for res in raw_google_results_list] if raw_google_results_list else []
                    }
                except Exception as e:
                    logger.error(f"Error en Google Dorks: {e}", exc_info=True); execution_errors.append(f"Google Dorks ({google_query_executed}): {str(e)}")
                    results_structured["google_dorks"] = {"query_executed": google_query_executed, "error": str(e), "results": []}
            else:
                msg = "Google Dorks omitido: API keys no configuradas."
                logger.warning(msg); execution_errors.append(msg)
                results_structured["google_dorks"] = {"query_executed": google_query_executed, "status": "omitted", "reason": msg, "results": []}
        else:
            msg = f"Google Dorks omitido para escenario '{current_scenario}'."
            logger.info(msg)
            results_structured["google_dorks"] = {"status": "omitted", "reason": msg, "results": []}
        
        # 5. Compilar prompt para DeepSeek usando los datos ESTRUCTURADOS
        # Las funciones de formateo a string se usarán aquí para construir el prompt
        temp_string_dns = format_dns_results_string(results_structured["dns"]) if results_structured["dns"] else "Datos DNS no disponibles o con error.\n"
        temp_string_nmap = format_nmap_results_string(results_structured["nmap"], url_dominio) if results_structured["nmap"] else "Datos Nmap no disponibles o con error.\n"
        temp_string_whois = format_whois_results_string(WhoisInfo(**results_structured["whois"]) if results_structured["whois"] and "error" not in results_structured["whois"] else None, url_dominio) if results_structured["whois"] else "Datos Whois no disponibles o con error.\n"
        temp_string_gdorks = format_google_dorks_results_string(results_structured["google_dorks"], google_query_executed) if results_structured["google_dorks"] and results_structured["google_dorks"].get("status") != "omitted" else results_structured["google_dorks"].get("reason","") + "\n" if results_structured["google_dorks"] else "Datos de Google Dorks no disponibles o con error.\n"


        prompt_parts = [f"Análisis de Seguridad para el objetivo: {url_dominio}\n"]
        prompt_parts.append(temp_string_dns)
        prompt_parts.append(temp_string_nmap)
        prompt_parts.append(temp_string_whois)
        if current_scenario in ["complete", "full"]:
            prompt_parts.append(temp_string_gdorks)
        
        prompt_parts.append(
            "Por favor, analiza la información de seguridad recopilada para el objetivo. "
            "Proporciona un resumen de los hallazgos clave, identifica posibles vulnerabilidades "
            "o áreas de preocupación relevantes para la seguridad, y sugiere recomendaciones "
            "generales de seguridad basadas estrictamente en los datos provistos. "
            "Responde en español."
        )
        deepseek_prompt = "\n".join(filter(None, prompt_parts))

        # 6. Consultar DeepSeek
        deepseek_analysis = "Análisis de DeepSeek no ejecutado o fallido."
        if self.deepseek_api_key:
            try:
                logger.info(f"Enviando datos a DeepSeek para análisis del objetivo {url_dominio}...")
                deepseek_analysis = consultar_deepseek(deepseek_prompt)
            except Exception as e:
                logger.error(f"Error al consultar DeepSeek: {e}", exc_info=True); execution_errors.append(f"DeepSeek API: {str(e)}")
                deepseek_analysis = f"Error al contactar o procesar la respuesta de DeepSeek: {str(e)}"
        else:
            logger.warning(f"No se consultará DeepSeek: DEEPSEEK_API_KEY no configurada."); execution_errors.append("DeepSeek API: Clave no configurada.")

        return {
            "url_dominio": url_dominio,
            "scenario": current_scenario,
            "scan_results": results_structured, # Devuelve los datos estructurados
            "deepseek_analysis": deepseek_analysis,
            "execution_errors": execution_errors
        }

# --- FUNCIÓN generate_html_report (MEJORADA) ---
def generate_html_report(scan_data_dict: Dict[str, Any]) -> str:
    url_dominio = html.escape(scan_data_dict.get("url_dominio", "N/A"))
    scenario = html.escape(scan_data_dict.get("scenario", "N/A").capitalize())
    
    results_structured = scan_data_dict.get("scan_results", {})
    deepseek_analysis = html.escape(scan_data_dict.get("deepseek_analysis", "Análisis de DeepSeek no disponible."))
    execution_errors = scan_data_dict.get("execution_errors", [])

    # Inicia el contenido HTML
    html_content = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Escaneo: {url_dominio}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f4f7f6; color: #333; }}
        .container {{ width: 90%; max-width: 1000px; margin: 20px auto; background-color: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; text-align: center; border-bottom: 3px solid #3498db; padding-bottom: 15px; margin-bottom:20px; }}
        h2 {{ color: #3498db; margin-top: 30px; border-bottom: 2px solid #aec6cf; padding-bottom: 8px; }}
        .section {{ margin-bottom: 25px; padding: 20px; background-color: #ffffff; border: 1px solid #e0e0e0; border-radius: 6px; }}
        .section h2 {{ margin-top: 0; }}
        pre {{ background-color: #2d2d2d; color: #f0f0f0; padding: 15px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; font-family: 'Consolas', 'Courier New', monospace; font-size: 0.9em; border: 1px solid #444; line-height: 1.6; overflow-x: auto; }}
        .error {{ color: #e74c3c; font-weight: bold; }}
        .error-section {{ background-color: #fdd; border-left: 5px solid #e74c3c; padding:15px; }}
        ul {{ list-style-type: disc; padding-left: 20px; }}
        ul li {{ margin-bottom: 8px; }}
        ul li b {{ color: #2980b9; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; box-shadow: 0 2px 3px rgba(0,0,0,0.1); }}
        th, td {{ text-align: left; padding: 10px; border: 1px solid #ddd; }}
        th {{ background-color: #3498db; color: white; font-weight: bold; }}
        tr:nth-child(even) {{ background-color: #f7f9f9; }}
        .details-block p {{ margin: 5px 0; }}
        .code {{ font-family: 'Consolas', 'Courier New', monospace; background-color: #e9e9e9; padding: 2px 5px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Reporte de Escaneo de Seguridad</h1>
        <div class="section">
            <h2>Información General</h2>
            <p><strong>Objetivo:</strong> <span class="code">{url_dominio}</span></p>
            <p><strong>Escenario:</strong> {scenario}</p>
        </div>
    """

    # Sección DNS
    dns_data = results_structured.get("dns", {})
    html_content += "<div class='section'><h2>Resultados DNS</h2>"
    if dns_data.get("error"):
        html_content += f"<p class='error'>Error: {html.escape(dns_data['error'])}</p>"
    elif dns_data.get("details"):
        dns_details_map = dns_data["details"]
        if isinstance(dns_details_map, dict) and any(dns_details_map.values()):
            html_content += "<ul>"
            for record_type, records in dns_details_map.items():
                html_content += f"<li><b>{html.escape(record_type)}:</b>"
                if records:
                    html_content += "<ul>"
                    for record in records:
                        html_content += f"<li>{html.escape(str(record))}</li>"
                    html_content += "</ul>"
                else:
                    html_content += " (No se encontraron registros)"
                html_content += "</li>"
            html_content += "</ul>"
        else:
            html_content += "<p>No se encontraron registros DNS significativos.</p>"
    else:
        html_content += "<p>No se obtuvieron datos DNS.</p>"
    html_content += "</div>"

    # Sección Nmap
    nmap_hosts_list = results_structured.get("nmap", [])
    html_content += "<div class='section'><h2>Resultados Nmap</h2>"
    if isinstance(nmap_hosts_list, list) and nmap_hosts_list:
        for host_dict in nmap_hosts_list: # host_dict es un diccionario
            if host_dict.get("status") == "omitted":
                html_content += f"<p>Nmap omitido: {html.escape(host_dict.get('reason', ''))}</p>"
                break 
            html_content += f"<h3>Host: {html.escape(host_dict.get('ip', 'N/A'))}</h3>"
            html_content += f"<p><strong>Estado:</strong> {html.escape(host_dict.get('status', 'desconocido'))}</p>"
            if host_dict.get('error'):
                html_content += f"<p class='error'>Error Nmap: {html.escape(host_dict.get('error'))}</p>"
            
            ports_list = host_dict.get('ports', [])
            if ports_list:
                html_content += "<table><thead><tr><th>Puerto</th><th>Protocolo</th><th>Estado</th><th>Servicio</th></tr></thead><tbody>"
                for port_dict in ports_list: # port_dict es un diccionario
                    service_info_parts = []
                    service_map = port_dict.get('service', {})
                    if service_map:
                        if service_map.get('name'): service_info_parts.append(html.escape(service_map['name']))
                        if service_map.get('product'): service_info_parts.append(html.escape(service_map['product']))
                        if service_map.get('version'): service_info_parts.append(html.escape(service_map['version']))
                    service_str = " ".join(filter(None, service_info_parts)) if service_info_parts else "N/A"
                    html_content += f"<tr><td>{html.escape(port_dict.get('port','N/A'))}</td><td>{html.escape(port_dict.get('protocol','N/A'))}</td><td>{html.escape(port_dict.get('state','N/A'))}</td><td>{service_str}</td></tr>"
                html_content += "</tbody></table>"
            else:
                html_content += "<p>No se encontraron puertos abiertos o información no disponible.</p>"
            html_content += "<hr style='border:0; border-top:1px solid #eee; margin:15px 0;'>"
        if not nmap_hosts_list: # Si la lista está vacía pero no es None
             html_content += "<p>No se procesaron hosts Nmap.</p>"
    elif results_structured.get("nmap") and results_structured.get("nmap")[0].get("status") == "omitted": # Caso omitido en "basic"
         html_content += f"<p>Nmap omitido ({html.escape(results_structured.get('nmap')[0].get('reason', 'escenario básico'))}).</p>"
    else:
        html_content += "<p>No se obtuvieron datos Nmap o hubo un error general (revisar errores de ejecución).</p>"
    html_content += "</div>"

    # Sección Whois
    whois_dict = results_structured.get("whois", {})
    html_content += "<div class='section'><h2>Resultados Whois</h2>"
    if whois_dict and not whois_dict.get("error"):
        html_content += "<ul>"
        if whois_dict.get("domain_name"): html_content += f"<li><b>Nombre de Dominio:</b> {html.escape(', '.join(whois_dict['domain_name']))}</li>"
        if whois_dict.get("registrar"): html_content += f"<li><b>Registrador:</b> {html.escape(whois_dict['registrar'])}</li>"
        if whois_dict.get("creation_date"): html_content += f"<li><b>Fecha de Creación:</b> {html.escape(str(whois_dict['creation_date']))}</li>"
        if whois_dict.get("expiration_date"): html_content += f"<li><b>Fecha de Expiración:</b> {html.escape(str(whois_dict['expiration_date']))}</li>"
        if whois_dict.get("updated_date"): html_content += f"<li><b>Última Actualización:</b> {html.escape(str(whois_dict['updated_date']))}</li>"
        if whois_dict.get("name_servers"): html_content += f"<li><b>Servidores de Nombre:</b> {html.escape(', '.join(whois_dict['name_servers']))}</li>"
        if whois_dict.get("status"): html_content += f"<li><b>Estado:</b> {html.escape(', '.join(whois_dict['status']))}</li>"
        if whois_dict.get("emails"): html_content += f"<li><b>Emails:</b> {html.escape(', '.join(whois_dict['emails']))}</li>"
        if whois_dict.get("country"): html_content += f"<li><b>País:</b> {html.escape(whois_dict['country'])}</li>"
        html_content += "</ul>"
    elif whois_dict and whois_dict.get("error"):
        html_content += f"<p class='error'>Error Whois: {html.escape(whois_dict['error'])}</p>"
    else:
        html_content += "<p>No se obtuvieron datos Whois.</p>"
    html_content += "</div>"

    # Sección Google Dorks
    gorks_data = results_structured.get("google_dorks", {})
    html_content += "<div class='section'><h2>Resultados Google Dorks</h2>"
    query_executed_g = html.escape(gorks_data.get('query_executed', 'N/A'))
    if gorks_data.get("status") == "omitted":
        html_content += f"<p>Google Dorks omitido ({html.escape(gorks_data.get('reason', ''))}).</p>"
    elif gorks_data.get("error"):
        html_content += f"<p class='error'>Error Google Dorks (Query: {query_executed_g}): {html.escape(gorks_data['error'])}</p>"
    elif gorks_data.get("results"):
        gorks_results_list = gorks_data["results"]
        html_content += f"<p><strong>Query Ejecutado:</strong> <span class='code'>{query_executed_g}</span></p>"
        if gorks_results_list:
            html_content += "<ul>"
            for item_dict in gorks_results_list: # item_dict es un diccionario
                html_content += f"<li><b>Título:</b> {html.escape(item_dict.get('title','N/A'))}<br>"
                html_content += f"<b>Enlace:</b> <a href='{html.escape(item_dict.get('link',''))}' target='_blank'>{html.escape(item_dict.get('link',''))}</a><br>"
                html_content += f"<b>Fragmento:</b> {html.escape(item_dict.get('snippet','N/A'))}</li>"
            html_content += "</ul>"
        else:
            html_content += "<p>No se encontraron ítems para esta consulta.</p>"
    else:
        html_content += "<p>No se ejecutó Google Dorks o no hubo resultados.</p>"
    html_content += "</div>"
    
    # Análisis de DeepSeek
    html_content += f"""
    <div class="section">
        <h2>Análisis de DeepSeek</h2>
        <pre>{deepseek_analysis}</pre>
    </div>
    """

    # Errores de Ejecución
    if execution_errors:
        html_content += "<div class='section error-section'><h2>Errores de Ejecución Adicionales</h2><ul class='errors'>"
        for err in execution_errors:
            html_content += f"<li>{html.escape(err)}</li>"
        html_content += "</ul></div>"
    
    html_content += "    </div></body></html>" # Cierre de .container y body/html
    return html_content