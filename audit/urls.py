from django.urls import path
from . import views

app_name = 'audit'

urlpatterns = [
    # Web UI URLs
    path('', views.audit_dashboard_view, name='dashboard'),
    path('documents/<uuid:doc_id>/', views.document_audit_view, name='document_audit'),
    path('security-events/', views.security_events_view, name='security_events'),
    path('security-events/<uuid:event_id>/resolve/', views.resolve_security_event_view, name='resolve_event'),

    # REST API endpoints
    path('api/audit/', views.APIAuditLogListView.as_view(), name='api_audit_list'),
    path('api/documents/<uuid:pk>/audit/', views.APIDocumentAuditView.as_view(), name='api_document_audit'),
    path('api/admin/security-events/', views.APISecurityEventsView.as_view(), name='api_security_events'),
    path('api/admin/audit/verify/', views.APIVerifyAuditChainView.as_view(), name='api_audit_verify'),
]
