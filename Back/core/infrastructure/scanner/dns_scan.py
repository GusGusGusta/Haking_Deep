# security_apy/core/infrastructure/scanner/dns_scan.py
import dns.resolver # Solo necesitas dns.resolver para esta clase específica
import logging
from typing import List, Dict, Optional
# No necesitas importar WhoisInfo, NmapHost, NmapPort aquí si esta clase solo maneja DNS.
# Deberían ser importadas por las clases que las usan/retornan (ej. WhoisScanner, NmapScanner).
from core.domain.entities import DnsRecord # DnsRecord sí es relevante aquí.

# Configuración de logging (puede estar en un módulo de configuración central si lo prefieres)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DNSScanner:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()

    def resolve_records_raw(self, domain: str, record_types: Optional[List[str]] = None) -> Dict[str, List[str]]:
        """
        Resuelve varios tipos de registros DNS para un dominio dado.
        Retorna un diccionario donde las claves son los tipos de registro y los valores son listas de strings de los registros.
        """
        # Si no se especifican tipos de registro, usa una lista predeterminada.
        record_types = record_types or ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
        resolved_records: Dict[str, List[str]] = {} # Especificar el tipo para mayor claridad

        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                # Convierte cada respuesta a string. DnsRecord podría usarse aquí si quieres objetos más ricos.
                resolved_records[record_type] = [str(data) for data in answers]
            except dns.resolver.NoAnswer:
                logging.info(f"No se encontraron registros {record_type} para {domain}")
                resolved_records[record_type] = []
            except dns.resolver.NXDOMAIN:
                logging.error(f"El dominio no existe (NXDOMAIN): {domain} al consultar {record_type}")
                # Si el dominio no existe, probablemente no tenga sentido seguir buscando otros tipos de registros para él.
                # Puedes decidir si romper el bucle o continuar y obtener listas vacías.
                # Por ahora, lo dejamos que continúe para otros tipos, pero podrías retornar aquí.
                resolved_records[record_type] = [] # Asegura que la clave exista
            except dns.exception.Timeout:
                logging.warning(f"Timeout al resolver {record_type} para {domain}")
                resolved_records[record_type] = []
            except Exception as e:
                logging.error(f"Error inesperado al resolver {record_type} para {domain}: {e}")
                resolved_records[record_type] = []
        return resolved_records

# ------------------------------------------------------------------------------------
# NOTA IMPORTANTE:
# Los siguientes métodos estaban en tu dns_scan.py original dentro de DNSScanner:
# - get_whois_info_raw
# - scan_targets_raw
# - _parse_nmap_xml
#
# Para un diseño más limpio y coherente con tu scanner_adapter.py (que importa
# WhoisScanner y NmapScanner de otros módulos), estos métodos deberían estar en
# sus propias clases y archivos:
#
# 1. get_whois_info_raw -> en una clase WhoisScanner en core/infrastructure/scanner/whois_scan.py
#    (necesitaría importar `whois` y `WhoisInfo`)
#
# 2. scan_targets_raw y _parse_nmap_xml -> en una clase NmapScanner en core/infrastructure/scanner/nmap_scan.py
#    (necesitaría importar `subprocess`, `xml.etree.ElementTree`, `os`, `NmapHost`, `NmapPort`)
#
# Si decides NO separarlos y mantenerlos en DNSScanner, entonces tu scanner_adapter.py
# debería instanciar DNSScanner() también para WhoisScannerAdapter y NmapScannerAdapter,
# y no necesitarías los archivos whois_scan.py ni nmap_scan.py.
# ------------------------------------------------------------------------------------