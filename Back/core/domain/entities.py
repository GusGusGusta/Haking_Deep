# core/domain/entities.py
from typing import List, Dict, Optional
from pydantic import BaseModel

class GoogleDorkResult:
    def __init__(self, title: str, link: str, snippet: str):
        self.title = title
        self.link = link
        self.snippet = snippet

    def to_dict(self) -> Dict[str, str]:
        return {"title": self.title, "link": self.link, "snippet": self.snippet}

class DnsRecord:
    def __init__(self, type: str, value: List[str]):
        self.type = type
        self.value = value

class WhoisInfo:
    def __init__(self, registrar: Optional[str] = None, creation_date: Optional[str] = None,
                 expiration_date: Optional[str] = None, name_servers: Optional[List[str]] = None,
                 status: Optional[List[str]] = None, emails: Optional[List[str]] = None,
                 country: Optional[str] = None, whois_server: Optional[str] = None,
                 updated_date: Optional[str] = None, domain_name: Optional[List[str]] = None,
                 error: Optional[str] = None):
        self.registrar = registrar
        self.creation_date = creation_date
        self.expiration_date = expiration_date
        self.name_servers = name_servers if name_servers is not None else []
        self.status = status if status is not None else []
        self.emails = emails if emails is not None else []
        self.country = country
        self.whois_server = whois_server
        self.updated_date = updated_date
        self.domain_name = domain_name if domain_name is not None else []
        self.error = error

    def to_dict(self) -> Dict:
        return {
            "registrar": self.registrar,
            "creation_date": self.creation_date,
            "expiration_date": self.expiration_date,
            "name_servers": self.name_servers,
            "status": self.status,
            "emails": self.emails,
            "country": self.country,
            "whois_server": self.whois_server,
            "updated_date": self.updated_date,
            "domain_name": self.domain_name,
            "error": self.error,
        }

class NmapPort(BaseModel):
    port: str
    protocol: str
    state: str
    service: Optional[Dict[str, str]] = {}

class NmapHost(BaseModel):
    ip: str
    ports: List[NmapPort]
    status: Optional[str] = None
    error: Optional[str] = None