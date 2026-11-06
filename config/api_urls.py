"""
Centralized REST API Routing for TrustVault
Mounted at /api/
"""

from django.urls import path
import accounts.views as account_views
import documents.views as doc_views
import sharing.views as sharing_views
import audit.views as audit_views
import dashboard.views as dash_views

urlpatterns = [
    # Authentication Endpoints
    path('auth/login/', account_views.APILoginView.as_view(), name='api_auth_login'),
    path('auth/logout/', account_views.APILogoutView.as_view(), name='api_auth_logout'),
    path('auth/register/', account_views.APIRegisterView.as_view(), name='api_auth_register'),

    # User Management Endpoints
    path('users/', account_views.APIUserListView.as_view(), name='api_users_list'),
    path('users/me/', account_views.APICurrentUserView.as_view(), name='api_users_me'),
    path('users/<int:pk>/', account_views.APIUserDetailView.as_view(), name='api_users_detail'),

    # Document Endpoints
    path('documents/', doc_views.APIDocumentListCreateView.as_view(), name='api_documents_list_create'),
    path('documents/<uuid:pk>/', doc_views.APIDocumentDetailView.as_view(), name='api_documents_detail'),
    path('documents/<uuid:pk>/download/', doc_views.APIDocumentDownloadView.as_view(), name='api_documents_download'),
    path('documents/<uuid:pk>/restore/', doc_views.APIDocumentRestoreView.as_view(), name='api_documents_restore'),
    path('categories/', doc_views.APICategoryListView.as_view(), name='api_categories_list'),

    # Sharing & Permissions Endpoints
    path('documents/<uuid:pk>/permissions/', sharing_views.APIDocumentPermissionListCreateView.as_view(), name='api_doc_permissions'),
    path('permissions/<uuid:pk>/', sharing_views.APIPermissionDetailView.as_view(), name='api_permission_detail'),

    # Audit & Security Endpoints
    path('audit/', audit_views.APIAuditLogListView.as_view(), name='api_audit_list'),
    path('documents/<uuid:pk>/audit/', audit_views.APIDocumentAuditView.as_view(), name='api_document_audit'),
    path('admin/security-events/', audit_views.APISecurityEventsView.as_view(), name='api_admin_security_events'),
    path('admin/audit/verify/', audit_views.APIVerifyAuditChainView.as_view(), name='api_admin_audit_verify'),

    # Dashboard Metrics Endpoints
    path('dashboard/admin/', dash_views.APIAdminDashboardView.as_view(), name='api_dashboard_admin'),
    path('dashboard/owner/', dash_views.APIOwnerDashboardView.as_view(), name='api_dashboard_owner'),
    path('dashboard/viewer/', dash_views.APIViewerDashboardView.as_view(), name='api_dashboard_viewer'),
]
