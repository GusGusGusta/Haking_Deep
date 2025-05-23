# security_apy/core/infrastructure/scanner/whois_scan.py
import whois
import logging
from typing import List, Optional # Necesario para la entidad
from core.domain.entities import WhoisInfo # Asegúrate que la ruta a tu entidad es correcta

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class WhoisScanner:  # <--- ESTA ES LA LÍNEA CRUCIAL
    def get_whois_info_raw(self, domain: str) -> WhoisInfo:
        """
        Obtiene la información WHOIS para un dominio dado.
        Retorna un objeto WhoisInfo.
        """
        try:
            w = whois.whois(domain)

            def get_date_value(date_data):
                if isinstance(date_data, list):
                    return str(date_data[0]) if date_data else None
                return str(date_data) if date_data else None

            def get_list_value(list_data) -> Optional[List[str]]:
                if list_data is None:
                    return None
                if isinstance(list_data, list):
                    return [str(item) for item in list_data]
                return [str(list_data)]

            return WhoisInfo(
                domain_name=get_list_value(w.domain_name),
                registrar=str(w.registrar) if w.registrar else None,
                whois_server=str(w.whois_server) if w.whois_server else None,
                updated_date=get_date_value(w.updated_date),
                creation_date=get_date_value(w.creation_date),
                expiration_date=get_date_value(w.expiration_date),
                name_servers=get_list_value(w.name_servers),
                status=get_list_value(w.status),
                emails=get_list_value(w.emails),
                country=str(w.country) if hasattr(w, 'country') and w.country else None,
                error=None
            )
        except Exception as e:
            logging.error(f"Error al obtener WHOIS para {domain}: {e}")
            return WhoisInfo(domain_name=[domain] if domain else [], error=str(e))