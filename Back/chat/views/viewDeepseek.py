# security_apy/chat/views/viewDeepseek.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from ..services.deep_seek_service import consultar_deepseek
 
class DeepSeekView(APIView):

    def post(self, request):
        prompt = request.data.get("message", "")    
        if not prompt:
            return Response({"error": "Falta el mensaje."}, status=status.HTTP_400_BAD_REQUEST)

        respuesta = consultar_deepseek(prompt)
        return Response({"respuesta": respuesta})