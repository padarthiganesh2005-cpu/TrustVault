from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect
from django.http import JsonResponse
from accounts.views import login_view, logout_view, register_view

def root_redirect(request):
    if request.user.is_authenticated:
        return redirect('dashboard:index')
    return redirect('login')

def health_check(request):
    """Production health-check endpoint."""
    return JsonResponse({"status": "healthy", "service": "TrustVault", "version": "1.0.0"})

urlpatterns = [
    # Root
    path('', root_redirect, name='root'),
    path('health/', health_check, name='health_check'),

    # Core Authentication Shortcuts
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('register/', register_view, name='register'),

    # Web UI App URLs
    path('accounts/', include('accounts.urls')),
    path('dashboard/', include('dashboard.urls')),
    path('documents/', include('documents.urls')),
    path('sharing/', include('sharing.urls')),
    path('audit/', include('audit.urls')),

    # Centralized REST API Endpoints (/api/...)
    path('api/', include('config.api_urls')),

    # Django Admin (Protected for maintenance)
    path('system-admin/', admin.site.urls),
]
