from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db.models import Count, Q
from rest_framework import views, status, permissions
from rest_framework.response import Response

from accounts.models import CustomUser, UserRole
from documents.models import Document, DocumentCategory
from sharing.models import DocumentPermission
from audit.models import AuditLog, SecurityEvent, AuditEventType, ActionResult
from audit.services import verify_audit_chain

# =====================================================================
# Web Template Views
# =====================================================================

@login_required
def dashboard_index_view(request):
    """Router view directing users to their role-specific dashboard."""
    role = request.user.role
    if role == UserRole.ADMIN:
        return redirect('dashboard:admin')
    elif role == UserRole.OWNER:
        return redirect('dashboard:owner')
    else:
        return redirect('dashboard:viewer')

@login_required
def admin_dashboard_view(request):
    if not request.user.is_admin_role:
        raise PermissionDenied("Only administrators can access the executive administration dashboard.")

    total_users = CustomUser.objects.count()
    active_users = CustomUser.objects.filter(is_active=True).count()
    total_docs = Document.objects.count()
    active_grants = DocumentPermission.objects.filter(is_active=True).count()

    total_uploads = AuditLog.objects.filter(event_type=AuditEventType.DOCUMENT_UPLOAD, action_result=ActionResult.SUCCESS).count()
    total_downloads = AuditLog.objects.filter(event_type=AuditEventType.DOCUMENT_DOWNLOAD, action_result=ActionResult.SUCCESS).count()
    total_denied = AuditLog.objects.filter(action_result=ActionResult.DENIED).count()

    recent_security_events = SecurityEvent.objects.filter(is_resolved=False).order_by('-created_at')[:5]
    recent_audits = AuditLog.objects.all().order_by('-sequence_number')[:10]
    recent_users = CustomUser.objects.all().order_by('-date_joined')[:5]

    context = {
        'total_users': total_users,
        'active_users': active_users,
        'total_docs': total_docs,
        'active_grants': active_grants,
        'total_uploads': total_uploads,
        'total_downloads': total_downloads,
        'total_denied': total_denied,
        'recent_security_events': recent_security_events,
        'recent_audits': recent_audits,
        'recent_users': recent_users,
    }
    return render(request, 'dashboard/admin_dashboard.html', context)

@login_required
def owner_dashboard_view(request):
    user = request.user
    owned_docs = Document.objects.filter(owner=user, is_deleted=False).order_by('-created_at')
    owned_doc_ids = list(owned_docs.values_list('id', flat=True))

    total_owned = owned_docs.count()
    total_active_grants = DocumentPermission.objects.filter(
        document_id__in=owned_doc_ids,
        is_active=True
    ).count()

    recent_downloads = AuditLog.objects.filter(
        document_id__in=owned_doc_ids,
        event_type=AuditEventType.DOCUMENT_DOWNLOAD,
        action_result=ActionResult.SUCCESS
    ).order_by('-sequence_number')[:8]

    recent_denied = AuditLog.objects.filter(
        document_id__in=owned_doc_ids,
        action_result=ActionResult.DENIED
    ).order_by('-sequence_number')[:8]

    context = {
        'owned_docs': owned_docs[:10],
        'total_owned': total_owned,
        'total_active_grants': total_active_grants,
        'recent_downloads': recent_downloads,
        'recent_denied': recent_denied,
    }
    return render(request, 'dashboard/owner_dashboard.html', context)

@login_required
def viewer_dashboard_view(request):
    user = request.user
    # Only retrieve active permissions for non-deleted documents
    shared_permissions = DocumentPermission.objects.filter(
        user=user,
        is_active=True,
        document__is_deleted=False
    ).select_related('document', 'document__owner', 'document__category').order_by('-granted_at')

    context = {
        'shared_permissions': shared_permissions,
        'total_shared': shared_permissions.count(),
    }
    return render(request, 'dashboard/viewer_dashboard.html', context)


# =====================================================================
# REST API Endpoints
# =====================================================================

class APIAdminDashboardView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        if not request.user.is_admin_role:
            return Response({"error": "Admin role required."}, status=status.HTTP_403_FORBIDDEN)

        data = {
            "total_users": CustomUser.objects.count(),
            "active_users": CustomUser.objects.filter(is_active=True).count(),
            "total_documents": Document.objects.count(),
            "total_active_grants": DocumentPermission.objects.filter(is_active=True).count(),
            "total_uploads": AuditLog.objects.filter(event_type=AuditEventType.DOCUMENT_UPLOAD, action_result=ActionResult.SUCCESS).count(),
            "total_downloads": AuditLog.objects.filter(event_type=AuditEventType.DOCUMENT_DOWNLOAD, action_result=ActionResult.SUCCESS).count(),
            "failed_access_attempts": AuditLog.objects.filter(action_result=ActionResult.DENIED).count(),
            "unresolved_security_events": SecurityEvent.objects.filter(is_resolved=False).count(),
        }
        return Response(data)

class APIOwnerDashboardView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        owned_doc_ids = list(Document.objects.filter(owner=user).values_list('id', flat=True))

        data = {
            "total_documents_uploaded": len(owned_doc_ids),
            "documents_shared": DocumentPermission.objects.filter(document_id__in=owned_doc_ids, is_active=True).values('document_id').distinct().count(),
            "total_active_permissions": DocumentPermission.objects.filter(document_id__in=owned_doc_ids, is_active=True).count(),
            "recent_downloads_count": AuditLog.objects.filter(document_id__in=owned_doc_ids, event_type=AuditEventType.DOCUMENT_DOWNLOAD, action_result=ActionResult.SUCCESS).count(),
            "recent_denied_attempts_count": AuditLog.objects.filter(document_id__in=owned_doc_ids, action_result=ActionResult.DENIED).count(),
        }
        return Response(data)

class APIViewerDashboardView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        shared_perms = DocumentPermission.objects.filter(
            user=user,
            is_active=True,
            document__is_deleted=False
        ).select_related('document', 'document__owner', 'document__category')

        shared_docs_data = []
        for p in shared_perms:
            shared_docs_data.append({
                "document_id": str(p.document.id),
                "name": p.document.name,
                "owner": p.document.owner.username,
                "category": p.document.category.name if p.document.category else None,
                "permission_type": p.permission_type,
                "granted_at": p.granted_at,
                "download_url": f"/api/documents/{p.document.id}/download/"
            })

        return Response({
            "total_shared_documents": len(shared_docs_data),
            "documents": shared_docs_data
        })
