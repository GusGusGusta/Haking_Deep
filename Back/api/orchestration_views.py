# api/orchestration_views.py
import logging
import html # Importar para el error HTML en ReporteHTMLView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import HttpResponse 

from core.application.orchestration_service import OrchestrationService, generate_html_report

logger = logging.getLogger(__name__)

class BaseOrchestrationAPIView(APIView):
    scenario_name = None 

    def post(self, request, *args, **kwargs):
        if not self.scenario_name:
            logger.error("Escenario no definido en la vista de orquestación JSON.")
            return Response({"error": "Error interno del servidor"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        url_dominio_recibido = request.data.get('url_dominio')
        custom_gquery = request.data.get('gquery', None) 

        if not url_dominio_recibido:
            return Response({"error": "El parámetro 'url_dominio' es requerido"}, status=status.HTTP_400_BAD_REQUEST)

        logger.info(f"API JSON: Solicitud para escaneo '{self.scenario_name}' en objetivo: {url_dominio_recibido}")
        try:
            service = OrchestrationService()
            results_dict = service.run_scan(
                url_dominio=url_dominio_recibido, 
                scenario=self.scenario_name, 
                custom_gquery=custom_gquery
            )
            return Response(results_dict, status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception(f"Error API JSON ({self.scenario_name}) para {url_dominio_recibido}: {e}")
            return Response({"error": f"Error inesperado: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ConsultaCompletaJSONView(BaseOrchestrationAPIView):
    scenario_name = 'complete'

class ConsultaBasicaJSONView(BaseOrchestrationAPIView):
    scenario_name = 'basic'

class ReporteHTMLView(APIView):
    def post(self, request, *args, **kwargs):
        url_dominio_recibido = request.data.get('url_dominio')
        scenario_para_reporte = request.data.get('scenario', 'complete') 
        custom_gquery = request.data.get('gquery', None)

        if not url_dominio_recibido:
            return Response(
                {"error": "El parámetro 'url_dominio' es requerido."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if scenario_para_reporte not in ['basic', 'complete', 'full']:
             return Response(
                {"error": "El parámetro 'scenario' debe ser 'basic' o 'complete'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        logger.info(f"API HTML: Solicitud de reporte para '{scenario_para_reporte}' en objetivo: {url_dominio_recibido}")
        try:
            service = OrchestrationService()
            scan_data_dict = service.run_scan(
                url_dominio=url_dominio_recibido, 
                scenario=scenario_para_reporte, 
                custom_gquery=custom_gquery
            )
            
            html_string_report = generate_html_report(scan_data_dict)
            
            response = HttpResponse(html_string_report, content_type='text/html')
            filename = f"reporte_seguridad_{url_dominio_recibido.replace('.', '_')}_{scenario_para_reporte}.html"
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            
            return response
            
        except Exception as e:
            logger.exception(f"Error generando reporte HTML para {url_dominio_recibido}: {e}")
            error_html = f"<!DOCTYPE html><html lang='es'><head><title>Error</title></head><body><h1>Error al generar el reporte</h1><p>Detalles: {html.escape(str(e))}</p></body></html>"
            return HttpResponse(error_html, status=status.HTTP_500_INTERNAL_SERVER_ERROR, content_type='text/html')