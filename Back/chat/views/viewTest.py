from rest_framework.views import APIView
from rest_framework.response import Response

class TestView(APIView):
    def get(self, request):
        return Response({"message": "El endpoint de prueba funciona correctamente 🎉"})
