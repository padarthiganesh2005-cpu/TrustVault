from django.urls import path
from . import views

app_name = 'documents'

urlpatterns = [
    # Web UI URLs
    path('', views.document_list_view, name='list'),
    path('upload/', views.document_upload_view, name='upload'),
    path('<uuid:pk>/', views.document_detail_view, name='detail'),
    path('<uuid:pk>/download/', views.document_download_view, name='download'),
    path('<uuid:pk>/edit/', views.document_edit_view, name='edit'),
    path('<uuid:pk>/replace-version/', views.document_replace_version_view, name='replace_version'),
    path('<uuid:pk>/delete/', views.document_delete_view, name='delete'),
    path('<uuid:pk>/restore/', views.document_restore_view, name='restore'),

    # REST API endpoints
    path('api/documents/', views.APIDocumentListCreateView.as_view(), name='api_document_list_create'),
    path('api/documents/<uuid:pk>/', views.APIDocumentDetailView.as_view(), name='api_document_detail'),
    path('api/documents/<uuid:pk>/download/', views.APIDocumentDownloadView.as_view(), name='api_document_download'),
    path('api/documents/<uuid:pk>/restore/', views.APIDocumentRestoreView.as_view(), name='api_document_restore'),
    path('api/categories/', views.APICategoryListView.as_view(), name='api_category_list'),
]
