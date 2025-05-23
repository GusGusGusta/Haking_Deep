# security_api/api/serializers.py
from rest_framework import serializers
# from core.domain.entities import GoogleDorkResult, DnsRecord, WhoisInfo, NmapHost, NmapPort # Comentado si no se usan directamente

class GoogleDorkResultSerializer(serializers.Serializer):
    title = serializers.CharField()
    link = serializers.URLField()
    snippet = serializers.CharField()

class DnsRecordSerializer(serializers.Serializer):
    type = serializers.SerializerMethodField()
    value = serializers.SerializerMethodField()

    def get_type(self, obj: tuple) -> str:
        if isinstance(obj, tuple) and len(obj) > 0:
            return obj[0]
        return ""

    def get_value(self, obj: tuple) -> list:
        if isinstance(obj, tuple) and len(obj) > 1:
            return obj[1]
        return []

class WhoisInfoSerializer(serializers.Serializer):
    registrar = serializers.CharField(allow_null=True, required=False)
    creation_date = serializers.CharField(allow_null=True, required=False)
    expiration_date = serializers.CharField(allow_null=True, required=False)
    name_servers = serializers.ListField(child=serializers.CharField(), allow_null=True, required=False)
    status = serializers.ListField(child=serializers.CharField(), allow_null=True, required=False)
    emails = serializers.ListField(child=serializers.CharField(), allow_null=True, required=False)
    country = serializers.CharField(allow_null=True, required=False)
    whois_server = serializers.CharField(allow_null=True, required=False)
    updated_date = serializers.CharField(allow_null=True, required=False)
    domain_name = serializers.ListField(child=serializers.CharField(), allow_null=True, required=False)
    error = serializers.CharField(allow_null=True, required=False)

class NmapPortSerializer(serializers.Serializer): # Serializador DRF
    port = serializers.CharField()
    protocol = serializers.CharField()
    state = serializers.CharField()
    service = serializers.DictField(child=serializers.CharField(), allow_null=True, required=False)

class NmapHostSerializer(serializers.Serializer): # Serializador DRF
    ip = serializers.CharField()  # Cambiado a CharField para mayor flexibilidad (IPs o hostnames)
    
    # --- Campos Añadidos ---
    status = serializers.CharField(required=False, allow_null=True)
    error = serializers.CharField(required=False, allow_null=True)
    # --- Fin de Campos Añadidos ---
    
    ports = serializers.ListField(child=NmapPortSerializer()) # Usando NmapPortSerializer (DRF)

# --- Serializadores para los Requests ---

class GoogleDorkQuerySerializer(serializers.Serializer):
    query = serializers.CharField(required=True)

class DnsScanRequestSerializer(serializers.Serializer):
    domain = serializers.CharField(required=True)
    record_types = serializers.ListField(child=serializers.CharField(), required=False)

class WhoisScanRequestSerializer(serializers.Serializer):
    domain = serializers.CharField(required=True)

class NmapScanRequestSerializer(serializers.Serializer):
    targets = serializers.ListField(child=serializers.CharField(), required=True)