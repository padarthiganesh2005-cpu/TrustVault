from django.urls import path
from . import views

app_name = 'sharing'

urlpatterns = [
    # Web UI actions
    path('documents/<uuid:doc_id>/grant/', views.grant_permission_view, name='grant'),
    path('permissions/<uuid:pk>/update/', views.update_permission_view, name='update'),
    path('permissions/<uuid:pk>/revoke/', views.revoke_permission_view, name='revoke'),

    # REST API endpoints
    path('api/documents/<uuid:pk>/permissions/', views.APIDocumentPermissionListCreateView.as_view(), name='api_document_permissions'),
    path('api/permissions/<uuid:pk>/', views.APIPermissionDetailView.as_view(), name='api_permission_detail'),
]
