# security_apy/core/infrastructure/scanner/nmap_scan.py
import subprocess
import xml.etree.ElementTree as ET
import os
import logging
from typing import List, Optional # Optional puede ser útil para el retorno de _parse_nmap_xml si se prefiere
from core.domain.entities import NmapHost, NmapPort # Asegúrate que tus entidades NmapHost y NmapPort están definidas

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class NmapScanner:
    def scan_targets_raw(self, targets: List[str]) -> List[NmapHost]:
        """
        Escanea una lista de objetivos (IPs o hostnames) con Nmap.
        Retorna una lista de objetos NmapHost.
        """
        results: List[NmapHost] = []
        for target in targets:
            logging.info(f"Iniciando escaneo Nmap para el objetivo: {target}")
            # Crear un nombre de archivo XML temporal seguro
            safe_target_filename = "".join(c if c.isalnum() else "_" for c in target)
            xml_output_path = f"/tmp/nmap_{safe_target_filename}.xml" # Asegúrate que /tmp sea escribible

            try:
                # Ejecutar Nmap.
                process = subprocess.run(
                    ["nmap", target, "-A", "-Pn", "-T4", "-oX", xml_output_path],
                    check=True,        # Lanza CalledProcessError si Nmap devuelve un código de error
                    capture_output=True, # Captura stdout/stderr
                    text=True,           # Decodifica stdout/stderr como texto
                    timeout=300          # Timeout de 5 minutos (ejemplo)
                )

                # Verificar si el archivo XML se creó y no está vacío
                if os.path.exists(xml_output_path) and os.path.getsize(xml_output_path) > 0:
                    nmap_host_data = self._parse_nmap_xml(xml_output_path, original_target=target)
                    # _parse_nmap_xml ahora siempre debería devolver un NmapHost
                    results.append(nmap_host_data)
                else:
                    logging.warning(f"Archivo Nmap XML no generado o vacío para {target} en {xml_output_path}")
                    results.append(NmapHost(ip=target, ports=[], status="error_nmap_output", error="Archivo Nmap XML no generado o vacío"))

            except subprocess.CalledProcessError as e:
                logging.error(f"Error de Nmap para {target}: {e.stderr or e.stdout or str(e)}")
                results.append(NmapHost(ip=target, ports=[], status="error_nmap_execution", error=f"Fallo en ejecución de Nmap: {e.stderr or e.stdout or str(e)}"))
            except subprocess.TimeoutExpired:
                logging.error(f"Timeout durante escaneo Nmap de {target}")
                results.append(NmapHost(ip=target, ports=[], status="error_nmap_timeout", error="Timeout en escaneo Nmap"))
            except FileNotFoundError:
                logging.error("Comando Nmap no encontrado. Asegúrate de que Nmap esté instalado y en el PATH del sistema.")
                results.append(NmapHost(ip=target, ports=[], status="error_nmap_not_found", error="Comando Nmap no encontrado"))
                break # Si Nmap no se encuentra, no continuar con otros objetivos.
            except Exception as e: # Captura genérica para otros errores inesperados
                logging.error(f"Error inesperado durante escaneo Nmap de {target}: {e}")
                results.append(NmapHost(ip=target, ports=[], status="error_unexpected", error=f"Error inesperado: {str(e)}"))
            finally:
                # Limpiar el archivo XML temporal
                if os.path.exists(xml_output_path):
                    try:
                        os.remove(xml_output_path)
                    except OSError as e_os:
                        logging.error(f"Error al eliminar archivo Nmap XML {xml_output_path}: {e_os}")
        return results

    def _parse_nmap_xml(self, xml_path: str, original_target: str) -> NmapHost:
        """
        Parsea un archivo XML de salida de Nmap para un solo host.
        Retorna un objeto NmapHost.
        El argumento 'original_target' se usa como fallback si no se puede determinar la IP desde el XML.
        """
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            host_node = root.find("host")
            if host_node is None:
                logging.warning(f"No se encontró la etiqueta 'host' en {xml_path} para el objetivo {original_target}")
                return NmapHost(ip=original_target, ports=[], status="error_parsing_xml", error="No se encontró la etiqueta 'host' en la salida Nmap XML.")

            # Determinar la dirección IP desde la salida de Nmap
            address_node = host_node.find("address[@addrtype='ipv4']")
            if address_node is None:
                address_node = host_node.find("address[@addrtype='ipv6']") # Fallback a IPv6
            
            actual_ip = address_node.get("addr") if address_node is not None else original_target

            parsed_ports: List[NmapPort] = []
            ports_node = host_node.find("ports")
            if ports_node is not None:
                for port_node in ports_node.findall("port"):
                    state_node = port_node.find("state")
                    if state_node is None: # Debería existir para un puerto válido
                        continue

                    service_details = {}
                    service_node = port_node.find("service")
                    if service_node is not None:
                        service_details["name"] = service_node.get("name", "")
                        service_details["product"] = service_node.get("product", "")
                        service_details["version"] = service_node.get("version", "")
                        service_details["extrainfo"] = service_node.get("extrainfo", "")
                        # Puedes añadir más atributos si tu entidad NmapPort los requiere
                    
                    port_obj = NmapPort(
                        port=port_node.get("portid"),
                        protocol=port_node.get("protocol"),
                        state=state_node.get("state"),
                        service=service_details
                    )
                    parsed_ports.append(port_obj)
            
            # Determinar el estado final del host
            final_status = "unknown" # Default status
            error_message = None     # Default error message

            # Comprobar el estado del host desde la sección <status> dentro de <host>
            host_status_tag = host_node.find("status")
            if host_status_tag is not None:
                host_state_from_tag = host_status_tag.get("state")
                if host_state_from_tag == "up":
                    final_status = "up"
                elif host_state_from_tag == "down":
                    final_status = "down"
                    error_message = f"Host reportado como '{host_state_from_tag}' por Nmap (etiqueta status)."

            # Comprobar también <runstats> para una confirmación, esto puede ser más fiable.
            runstats_hosts_node = root.find("./runstats/hosts")
            if runstats_hosts_node is not None:
                if runstats_hosts_node.get("down", "0") == "1" and runstats_hosts_node.get("up", "0") == "0":
                    final_status = "down"
                    if error_message is None: # Solo sobrescribir si no hay un error más específico de la etiqueta status
                         error_message = "Host reportado como 'down' por Nmap (runstats)."
                elif runstats_hosts_node.get("up", "0") == "1":
                    # Si runstats dice up, y no teníamos un 'down' de la etiqueta status, es 'up'.
                    if final_status != "down": # No sobrescribir un 'down' ya detectado
                        final_status = "up"
            
            # Refinar el estado "up" basado en si se encontraron puertos
            if final_status == "up":
                if parsed_ports:
                    final_status = "up_with_open_ports" # O simplemente "up"
                else:
                    final_status = "up_no_open_ports"

            return NmapHost(ip=actual_ip, ports=parsed_ports, status=final_status, error=error_message)

        except ET.ParseError as e_parse:
            logging.error(f"Error al parsear Nmap XML desde {xml_path}: {e_parse}")
            return NmapHost(ip=original_target, ports=[], status="error_parsing_xml", error=f"Fallo al parsear Nmap XML: {str(e_parse)}")
        except Exception as e_gen: # Capturar otros errores inesperados durante el parseo
            logging.error(f"Error inesperado parseando {xml_path}: {e_gen}")
            return NmapHost(ip=original_target, ports=[], status="error_parsing_unexpected", error=f"Error inesperado parseando Nmap XML: {str(e_gen)}")