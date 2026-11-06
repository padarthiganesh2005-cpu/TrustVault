from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.utils import timezone
from rest_framework import views, generics, status, permissions
from rest_framework.response import Response

from .models import AuditLog, SecurityEvent, AuditEventType, ActionResult
from .serializers import AuditLogSerializer, SecurityEventSerializer
from .services import verify_audit_chain
from documents.models import Document

# =====================================================================
# Django Template Views
# =====================================================================

@login_required
def audit_dashboard_view(request):
    """
    Comprehensive audit log trail.
    - Administrators can inspect all vault activity.
    - Document owners can inspect activity across their owned documents.
    - Ordinary viewers cannot inspect broad audit logs.
    """
    user = request.user
    if user.is_admin_role:
        qs = AuditLog.objects.all()
    elif user.is_owner_role:
        # Owner can view audits where they are actor OR where document is owned by them
        owned_doc_ids = list(user.owned_documents.values_list('id', flat=True))
        qs = AuditLog.objects.filter(
            models_q_owner(user, owned_doc_ids)
        )
    else:
        raise PermissionDenied("You do not have permission to view system audit logs.")

    # Filter by Event Type
    event_type = request.GET.get('event_type')
    if event_type:
        qs = qs.filter(event_type=event_type)

    # Filter by Result
    result = request.GET.get('result')
    if result:
        qs = qs.filter(action_result=result)

    # Filter by Actor Username
    actor_q = request.GET.get('actor', '').strip()
    if actor_q:
        qs = qs.filter(actor_username__icontains=actor_q)

    # Verification state
    chain_verification = None
    if request.GET.get('verify') == '1':
        chain_verification = verify_audit_chain()

    logs = qs.order_by('-sequence_number')[:100]

    context = {
        'logs': logs,
        'event_types': AuditEventType.choices,
        'results': ActionResult.choices,
        'selected_event_type': event_type,
        'selected_result': result,
        'selected_actor': actor_q,
        'chain_verification': chain_verification,
        'is_admin': user.is_admin_role,
    }
    return render(request, 'audit/audit_dashboard.html', context)

def models_q_owner(user, owned_doc_ids):
    from django.db.models import Q
    return Q(actor=user) | Q(document_id__in=owned_doc_ids)

@login_required
def document_audit_view(request, doc_id):
    """Audit trail specific to a single document."""
    try:
        document = Document.objects.get(pk=doc_id)
    except Document.DoesNotExist:
        raise Http404("Document not found.")

    if not (document.owner_id == request.user.id or request.user.is_admin_role):
        raise PermissionDenied("Only the document owner or an administrator can inspect document audit trails.")

    logs = AuditLog.objects.filter(document_id=document.id).order_by('-sequence_number')[:100]

    context = {
        'document': document,
        'logs': logs,
    }
    return render(request, 'audit/document_audit.html', context)

@login_required
def security_events_view(request):
    """Administrator-only security alerts overview."""
    if not request.user.is_admin_role:
        raise PermissionDenied("Only administrators can monitor security events.")

    events = SecurityEvent.objects.all().order_by('-created_at')[:100]
    return render(request, 'audit/security_events.html', {'events': events})

@login_required
def resolve_security_event_view(request, event_id):
    """Admin resolves a security alert."""
    if not request.user.is_admin_role:
        raise PermissionDenied("Only administrators can resolve security events.")

    event = get_object_or_404(SecurityEvent, pk=event_id)
    event.is_resolved = True
    event.resolved_by = request.user
    event.resolved_at = timezone.now()
    event.save()
    messages.success(request, f"Security event '{event.event_type}' marked as resolved.")
    return redirect('audit:security_events')


# =====================================================================
# REST API Endpoints
# =====================================================================

class APIAuditLogListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AuditLogSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_admin_role:
            qs = AuditLog.objects.all()
        elif user.is_owner_role:
            owned_doc_ids = list(user.owned_documents.values_list('id', flat=True))
            qs = AuditLog.objects.filter(models_q_owner(user, owned_doc_ids))
        else:
            return AuditLog.objects.none()

        event_type = self.request.query_params.get('event_type')
        if event_type:
            qs = qs.filter(event_type=event_type)

        result = self.request.query_params.get('result')
        if result:
            qs = qs.filter(action_result=result)

        doc_id = self.request.query_params.get('document_id')
        if doc_id:
            qs = qs.filter(document_id=doc_id)

        return qs.order_by('-sequence_number')

class APIDocumentAuditView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AuditLogSerializer

    def get_queryset(self):
        doc_id = self.kwargs['pk']
        user = self.request.user
        try:
            document = Document.objects.get(pk=doc_id)
        except Document.DoesNotExist:
            raise Http404("Document does not exist.")

        if document.owner_id != user.id and not user.is_admin_role:
            raise PermissionDenied("Only the document owner or an administrator can inspect document audit trails.")

        return AuditLog.objects.filter(document_id=document.id).order_by('-sequence_number')

class APISecurityEventsView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = SecurityEventSerializer

    def get_queryset(self):
        if not self.request.user.is_admin_role:
            raise PermissionDenied("Only administrators can access security event alerts.")
        return SecurityEvent.objects.all().order_by('-created_at')

class APIVerifyAuditChainView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if not request.user.is_admin_role:
            return Response(
                {"error": "Only administrators can run cryptographic audit chain verifications."},
                status=status.HTTP_403_FORBIDDEN
            )
        verification_result = verify_audit_chain()
        return Response(verification_result)
