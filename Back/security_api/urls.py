# security_api/urls.py (o el principal de tu proyecto)
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')), # Esta línea ya incluye todas las URLs de tu app 'api'
    # path('api/', include('chat.urls')), # Si también tienes URLs de chat bajo /api/
]