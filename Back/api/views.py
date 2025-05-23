# security_api/api/views.py
import os
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from dotenv import load_dotenv
from .serializers import (
    GoogleDorkQuerySerializer, GoogleDorkResultSerializer,
    DnsScanRequestSerializer, DnsRecordSerializer,
    WhoisScanRequestSerializer, WhoisInfoSerializer,
    NmapScanRequestSerializer, NmapHostSerializer
)
from core.application.use_cases import GoogleDorkUseCase, DnsScanUseCase, WhoisScanUseCase, NmapScanUseCase

def load_api_keys():
    load_dotenv()
    api_key = os.getenv('API_KEY_SEARCH_GOOGLE')
    search_engine_id = os.getenv('SEARCH_ENGINE_ID')
    shodan_api_key = os.getenv("SHODAN_API_KEY") # Asegúrate de tener esta variable en .env
    return api_key, search_engine_id, shodan_api_key

class GoogleDorkView(APIView):
    def post(self, request):
        serializer = GoogleDorkQuerySerializer(data=request.data)
        if serializer.is_valid():
            query = serializer.validated_data['query']
            api_key, search_engine_id, _ = load_api_keys()
            if api_key and search_engine_id:
                use_case = GoogleDorkUseCase()
                results = use_case.execute(query)
                if results:
                    result_serializer = GoogleDorkResultSerializer(results, many=True)
                    return Response(result_serializer.data, status=status.HTTP_200_OK)
                else:
                    return Response({"message": "No se encontraron resultados para la búsqueda."}, status=status.HTTP_204_NO_CONTENT)
            else:
                return Response({"error": "API Key o Search Engine ID no configurados."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DnsScanView(APIView):
    def post(self, request):
        serializer = DnsScanRequestSerializer(data=request.data)
        if serializer.is_valid():
            domain = serializer.validated_data['domain']
            record_types = serializer.validated_data.get('record_types')
            use_case = DnsScanUseCase()
            results = use_case.execute(domain, record_types)
            result_serializer = DnsRecordSerializer(results.items(), many=True)
            return Response(result_serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class WhoisScanView(APIView):
    def post(self, request):
        serializer = WhoisScanRequestSerializer(data=request.data)
        if serializer.is_valid():
            domain = serializer.validated_data['domain']
            use_case = WhoisScanUseCase()
            result = use_case.execute(domain)
            result_serializer = WhoisInfoSerializer(result)
            return Response(result_serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class NmapScanView(APIView):
    def post(self, request):
        serializer = NmapScanRequestSerializer(data=request.data)
        if serializer.is_valid():
            targets = serializer.validated_data['targets']
            use_case = NmapScanUseCase()
            results = use_case.execute(targets) # Esto es List[NmapHost] (modelos Pydantic)
            
            # Aquí es donde los modelos Pydantic se convierten para la respuesta:
            result_serializer = NmapHostSerializer(results, many=True) 
            
            return Response(result_serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)