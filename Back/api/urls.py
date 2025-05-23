# api/urls.py
from django.urls import path
from .views import GoogleDorkView, DnsScanView, WhoisScanView, NmapScanView 
from .orchestration_views import (
    ConsultaCompletaJSONView, 
    ConsultaBasicaJSONView, 
    ReporteHTMLView  # Asegúrate que ReporteHTMLView esté importada
)

urlpatterns = [
    # Rutas existentes para escaneos individuales (opcional)
    # path('google-dorks/', GoogleDorkView.as_view(), name='google_dorks'),
    # path('dns-scan/', DnsScanView.as_view(), name='dns_scan'),
    # path('whois-scan/', WhoisScanView.as_view(), name='whois_scan'),
    # path('nmap-scan/', NmapScanView.as_view(), name='nmap_scan'),

    # Rutas para los servicios de orquestación JSON
    path('consulta_completa_json/', ConsultaCompletaJSONView.as_view(), name='api-consulta-completa-json'),
    path('consulta_basica_json/', ConsultaBasicaJSONView.as_view(), name='api-consulta-basica-json'),
    
    # Ruta para el reporte HTML
    path('reporte_html/', ReporteHTMLView.as_view(), name='api-reporte-html'), 
]