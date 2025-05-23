# api/urls.py
from django.urls import path
# Vistas existentes para escaneos individuales
from .views import GoogleDorkView, DnsScanView, WhoisScanView, NmapScanView # Asumo que estas están en api/views.py

# Importa tus nuevas vistas de orquestación
from .orchestration_views import ConsultaCompletaView, ConsultaBasicaView # Si las pusiste en api/orchestration_views.py

urlpatterns = [
    # Rutas existentes para escaneos individuales
    path('google-dorks/', GoogleDorkView.as_view(), name='google_dorks'),
    path('dns-scan/', DnsScanView.as_view(), name='dns_scan'),
    path('whois-scan/', WhoisScanView.as_view(), name='whois_scan'),
    path('nmap-scan/', NmapScanView.as_view(), name='nmap_scan'),

    # NUEVAS RUTAS para los servicios de orquestación
    # Estas rutas resultarán en /api/consulta_completa/ y /api/consulta_basica/
    # debido al prefijo 'api/' en tu urls.py principal del proyecto.
    path('consulta_completa/', ConsultaCompletaView.as_view(), name='api-consulta-completa'),
    path('consulta_basica/', ConsultaBasicaView.as_view(), name='api-consulta-basica'),
]