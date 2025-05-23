# security_apy/chat/urls.py
from django.urls import path
from .views.viewTest import TestView
from .views.viewDeepseek import DeepSeekView

urlpatterns = [
    path('test/', TestView.as_view(), name='test-endpoint'),
    path('deepseek/', DeepSeekView.as_view(), name='deepseek-endpoint')
]
