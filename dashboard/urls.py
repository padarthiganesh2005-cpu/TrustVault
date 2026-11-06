from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    # Web UI URLs
    path('', views.dashboard_index_view, name='index'),
    path('admin/', views.admin_dashboard_view, name='admin'),
    path('owner/', views.owner_dashboard_view, name='owner'),
    path('viewer/', views.viewer_dashboard_view, name='viewer'),

    # REST API Endpoints
    path('api/dashboard/admin/', views.APIAdminDashboardView.as_view(), name='api_admin_dashboard'),
    path('api/dashboard/owner/', views.APIOwnerDashboardView.as_view(), name='api_owner_dashboard'),
    path('api/dashboard/viewer/', views.APIViewerDashboardView.as_view(), name='api_viewer_dashboard'),
]
