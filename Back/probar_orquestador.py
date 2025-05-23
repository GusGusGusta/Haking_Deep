import logging
import json # Para imprimir el diccionario de forma más legible

# Asegúrate de que la ruta de importación sea correcta según la estructura de tu proyecto
from core.application.orchestration_service import OrchestrationService

# Configuración básica de logging para ver los mensajes del servicio
# Esto te mostrará los logs INFO, WARNING, ERROR que definiste en OrchestrationService
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Crear una instancia del servicio de orquestación
try:
    orchestrator = OrchestrationService()
except Exception as e:
    logging.error(f"Error al instanciar OrchestrationService: {e}", exc_info=True)
    exit()

# Definir el objetivo y el escenario para la prueba
# Usa un dominio público y seguro para probar, como example.com
# o un dominio/IP que tengas permiso para escanear.
target_a_escanear = "example.com" 
# target_a_escanear = "scanme.nmap.org" # Otro sitio de prueba para Nmap
escenario_de_prueba = "full"  # Asumiendo que 'full' es el escenario que ejecuta todos los módulos

# Opcional: Si quieres probar con una consulta de Google Dorks personalizada
# query_google_personalizada = "intitle:\"Login Page\" site:example.com"
query_google_personalizada = None


# Ejecutar el escaneo
print(f"Iniciando prueba de OrchestrationService para el objetivo: {target_a_escanear}, escenario: {escenario_de_prueba}...")
try:
    resultados_escaneo = orchestrator.run_scan(
        target=target_a_escanear, 
        scenario=escenario_de_prueba,
        custom_gquery=query_google_personalizada
    )

    # Imprimir los resultados de forma legible
    print("\n--- RESULTADOS COMPLETOS DEL ESCANEO ---")
    print(json.dumps(resultados_escaneo, indent=4, ensure_ascii=False)) # ensure_ascii=False por si hay tildes

    # Puedes acceder a partes específicas si lo deseas:
    # print("\n--- ANÁLISIS DE DEEPSEEK ---")
    # print(resultados_escaneo.get("deepseek_analysis", "No disponible"))

    # print("\n--- ERRORES DE EJECUCIÓN (si los hubo) ---")
    # if resultados_escaneo.get("execution_errors"):
    #     for error in resultados_escaneo["execution_errors"]:
    #         print(f"- {error}")
    # else:
    #     print("No se reportaron errores de ejecución.")

except FileNotFoundError as e:
    logging.error(f"Error de Nmap (FileNotFoundError): {e}. Asegúrate de que Nmap esté instalado y en el PATH.")
    print(f"ERROR: Nmap no encontrado. Por favor, instálalo y asegúrate de que esté en el PATH del sistema. ({e})")
except Exception as e:
    logging.error(f"Ocurrió un error inesperado durante la ejecución de run_scan: {e}", exc_info=True)
    print(f"ERROR INESPERADO: {e}")

print("\nPrueba finalizada.")