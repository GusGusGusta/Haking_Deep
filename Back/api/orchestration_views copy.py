# api/orchestration_views.py
import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from core.application.orchestration_service import OrchestrationService

logger = logging.getLogger(__name__)

class BaseOrchestrationView(APIView):
    scenario_name = None 

    def post(self, request, *args, **kwargs):
        if not self.scenario_name:
            logger.error("Escenario no definido en la vista de orquestación.")
            return Response(
                {"error": "Error interno del servidor: Escenario no configurado."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # CAMBIO: 'target' renombrado a 'url_dominio'
        url_dominio_recibido = request.data.get('url_dominio')
        custom_gquery = request.data.get('gquery', None) 

        if not url_dominio_recibido:
            return Response(
                {"error": "El parámetro 'url_dominio' es requerido en el cuerpo de la solicitud."},
                status=status.HTTP_400_BAD_REQUEST
            )

        logger.info(f"API: Recibida solicitud para escaneo '{self.scenario_name}' en objetivo: {url_dominio_recibido}")
        try:
            service = OrchestrationService()
            # CAMBIO: Pasar 'url_dominio'
            results = service.run_scan(
                url_dominio=url_dominio_recibido, 
                scenario=self.scenario_name, 
                custom_gquery=custom_gquery
            )
            
            return Response(results, status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception(f"Error inesperado en la API de orquestación ({self.scenario_name}) para objetivo {url_dominio_recibido}: {e}")
            return Response(
                {"error": f"Ocurrió un error inesperado durante el escaneo: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ConsultaCompletaView(BaseOrchestrationView):
    scenario_name = 'complete'

class ConsultaBasicaView(BaseOrchestrationView):
    scenario_name = 'basic'