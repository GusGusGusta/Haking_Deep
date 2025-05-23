# security_apy/chat/services/deep_seek_service.py
import os
from dotenv import load_dotenv
import requests
# Importar excepciones específicas de requests
from requests.exceptions import Timeout, ConnectionError, HTTPError, RequestException, SSLError 
import urllib3 # Necesario para deshabilitar advertencias si usas verify=False
import json
# Las siguientes importaciones no son necesarias directamente en este archivo de servicio:
# from django.views.decorators.csrf import csrf_exempt 
# from django.http import JsonResponse 

load_dotenv()

def consultar_deepseek(prompt: str) -> str:
    url = "https://api.deepseek.com/chat/completions"
    api_key = os.getenv('DEEPSEEK_API_KEY')

    if not api_key:
        return "Error: La variable de entorno DEEPSEEK_API_KEY no está configurada."

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "deepseek-chat",  # o "deepseek-coder" si usas el modelo para código
        "messages": [
            {"role": "system", "content": "Eres un asistente útil que responde en español."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3,
        "max_tokens": 5000 # Considera si este límite es adecuado para tus reportes
    }

    try:
        # --- INICIO DE MODIFICACIÓN PARA SSL ---
        # Deshabilitar advertencias de solicitud insegura cuando verify=False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # ADVERTENCIA DE SEGURIDAD: 
        # verify=False deshabilita la verificación SSL. Esto puede exponer tu conexión a riesgos
        # de seguridad como ataques "man-in-the-middle". 
        # Úsalo solo si entiendes las implicaciones y preferiblemente no en producción.
        # La solución ideal es arreglar el problema de certificados en tu sistema (Opción 1).
        response = requests.post(url, headers=headers, json=payload, timeout=70, verify=False)
        # --- FIN DE MODIFICACIÓN PARA SSL ---

        # Manejar errores HTTP con claridad
        if response.status_code == 402:
            return "Tu cuenta de DeepSeek no tiene crédito o acceso habilitado. Verifica tu plan en https://platform.deepseek.com"

        response.raise_for_status() # Lanza una excepción para códigos de error HTTP (4xx o 5xx)

        data = response.json()
        if data.get("choices") and len(data["choices"]) > 0 and data["choices"][0].get("message"):
            return data["choices"][0]["message"]["content"].strip()
        else:
            # Manejar respuesta inesperada de la API que no sigue el formato esperado
            return f"Respuesta inesperada de DeepSeek API: {json.dumps(data)}"


    except Timeout: # Especificar requests.exceptions.Timeout si no se importó directamente
        return "Tiempo de espera agotado al contactar DeepSeek."
    except SSLError as ssl_err: # Manejar específicamente el SSLError
         return f"Error de SSL al conectar con DeepSeek: {str(ssl_err)}. Se intentó con verify=False. Si el error persiste, revisa la conectividad o el estado del servicio DeepSeek."
    except ConnectionError as conn_err: # Especificar requests.exceptions.ConnectionError
        return f"No se pudo establecer conexión con DeepSeek. Verifica tu conexión a internet. Detalle: {str(conn_err)}"
    except HTTPError as http_err: # Especificar requests.exceptions.HTTPError
        return f"Error HTTP de DeepSeek: {http_err.response.status_code} - {http_err.response.text}"
    except RequestException as req_err: # Especificar requests.exceptions.RequestException
        return f"Error de solicitud general con DeepSeek: {str(req_err)}"
    except json.JSONDecodeError: # Si la respuesta no es un JSON válido
        return f"No se pudo decodificar la respuesta JSON de DeepSeek. Respuesta recibida: {response.text if 'response' in locals() else 'No response object'}"
    except KeyError: # Si la estructura del JSON no es la esperada
        return f"La respuesta JSON de DeepSeek no tiene la estructura esperada (choices/message/content). Respuesta: {json.dumps(data) if 'data' in locals() else 'No data object'}"
    except Exception as e:
        return f"Error inesperado al procesar la solicitud a DeepSeek: {str(e)}"