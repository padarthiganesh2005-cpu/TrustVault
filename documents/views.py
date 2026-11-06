from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_POST
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponseForbidden
from django.utils import timezone
from django.db.models import Q
from rest_framework import views, generics, status, permissions
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser

from .models import Document, DocumentCategory, DocumentVersion
from .forms import DocumentUploadForm, DocumentEditForm, DocumentVersionReplaceForm
from .serializers import (
    DocumentDetailSerializer,
    DocumentUploadSerializer,
    DocumentCategorySerializer,
    DocumentVersionSerializer
)
from .services import (
    can_view_document,
    can_download_document,
    can_edit_document,
    can_delete_document,
    can_manage_permissions,
    can_restore_document,
    get_accessible_documents_queryset,
    upload_document,
    replace_document_version,
    soft_delete_document,
    restore_document,
    serve_secure_file
)
from audit.services import record_audit_event
from audit.models import AuditEventType, ActionResult
from sharing.forms import GrantPermissionForm

# =====================================================================
# Django Template Views
# =====================================================================

@login_required
def document_list_view(request):
    """
    Search and filter accessible documents.
    Backend query strictly confines results to authorized documents only.
    """
    user = request.user
    qs = get_accessible_documents_queryset(user)

    # Search query
    q = request.GET.get('q', '').strip()
    if q:
        qs = qs.filter(
            Q(name__icontains=q) |
            Q(description__icontains=q) |
            Q(tags__icontains=q) |
            Q(owner__username__icontains=q)
        )

    # Category filter
    category_id = request.GET.get('category', '').strip()
    if category_id:
        qs = qs.filter(category_id=category_id)

    # File type / extension filter
    ext = request.GET.get('ext', '').strip()
    if ext:
        qs = qs.filter(file_extension__iexact=ext)

    # Date range filters
    date_filter = request.GET.get('date', '').strip()
    now = timezone.now()
    if date_filter == 'today':
        qs = qs.filter(created_at__date=now.date())
    elif date_filter == '7days':
        qs = qs.filter(created_at__gte=now - timezone.timedelta(days=7))
    elif date_filter == '30days':
        qs = qs.filter(created_at__gte=now - timezone.timedelta(days=30))

    categories = DocumentCategory.objects.all()

    context = {
        'documents': qs,
        'categories': categories,
        'selected_q': q,
        'selected_category': category_id,
        'selected_ext': ext,
        'selected_date': date_filter,
    }
    return render(request, 'documents/document_list.html', context)

@login_required
def document_detail_view(request, pk):
    """
    View document details, version history, and permission roster.
    Unauthorized view attempts trigger audit logging and return 403.
    """
    try:
        document = Document.objects.select_related('owner', 'category').get(pk=pk)
    except Document.DoesNotExist:
        raise Http404("Document does not exist.")

    if not can_view_document(request.user, document):
        record_audit_event(
            event_type=AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT,
            action_result=ActionResult.DENIED,
            actor=request.user,
            document_id=document.id,
            document_name=document.name,
            metadata={"action": "view_details", "reason": "No active permission or ownership."},
            request=request
        )
        return render(request, 'errors/403.html', {'message': "Access Denied: You do not have permission to view this document."}, status=403)

    # Record view audit
    record_audit_event(
        event_type=AuditEventType.DOCUMENT_VIEW,
        action_result=ActionResult.SUCCESS,
        actor=request.user,
        document_id=document.id,
        document_name=document.name,
        request=request
    )

    is_owner = (document.owner_id == request.user.id)
    is_editor = can_edit_document(request.user, document)
    versions = document.versions.select_related('uploaded_by').all()
    active_permissions = document.permissions.filter(is_active=True).select_related('user', 'granted_by')
    permission_history = document.permission_history.select_related('target_user', 'performed_by').all()[:15]

    grant_form = GrantPermissionForm(document=document) if is_owner else None
    version_form = DocumentVersionReplaceForm() if is_editor else None

    context = {
        'document': document,
        'is_owner': is_owner,
        'is_editor': is_editor,
        'versions': versions,
        'active_permissions': active_permissions,
        'permission_history': permission_history,
        'grant_form': grant_form,
        'version_form': version_form,
    }
    return render(request, 'documents/document_detail.html', context)

@login_required
def document_upload_view(request):
    """Upload a new document."""
    # Check if user is Document Owner or Admin
    if not (request.user.is_owner_role or request.user.is_admin_role):
        messages.error(request, "Only Document Owners or Administrators can upload documents.")
        return redirect('dashboard:index')

    if request.method == 'POST':
        form = DocumentUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                doc = upload_document(
                    user=request.user,
                    file_obj=request.FILES['file'],
                    name=form.cleaned_data['name'],
                    description=form.cleaned_data.get('description', ''),
                    category=form.cleaned_data.get('category'),
                    tags=form.cleaned_data.get('tags', ''),
                    request=request
                )
                messages.success(request, f"Document '{doc.name}' uploaded successfully to secure private storage.")
                return redirect('documents:detail', pk=doc.id)
            except Exception as e:
                messages.error(request, f"Upload rejected: {str(e)}")
    else:
        form = DocumentUploadForm()

    return render(request, 'documents/document_upload.html', {'form': form})

@login_required
def document_download_view(request, pk):
    """
    Secure file download view.
    Checks authorization dynamically before streaming file.
    """
    try:
        document = Document.objects.get(pk=pk)
    except Document.DoesNotExist:
        raise Http404("Document does not exist.")

    version_str = request.GET.get('version')
    version_num = int(version_str) if version_str and version_str.isdigit() else None

    return serve_secure_file(request, document, version_number=version_num)

@login_required
def document_edit_view(request, pk):
    """Edit document metadata."""
    document = get_object_or_404(Document, pk=pk)
    if not can_edit_document(request.user, document):
        record_audit_event(
            event_type=AuditEventType.UNAUTHORIZED_MODIFICATION_ATTEMPT,
            action_result=ActionResult.DENIED,
            actor=request.user,
            document_id=document.id,
            document_name=document.name,
            metadata={"action": "edit_metadata"},
            request=request
        )
        raise PermissionDenied("You do not have permission to edit this document.")

    if request.method == 'POST':
        form = DocumentEditForm(request.POST, instance=document)
        if form.is_valid():
            form.save()
            record_audit_event(
                event_type=AuditEventType.DOCUMENT_EDIT,
                action_result=ActionResult.SUCCESS,
                actor=request.user,
                document_id=document.id,
                document_name=document.name,
                metadata={"updated_fields": list(form.changed_data)},
                request=request
            )
            messages.success(request, "Document metadata updated successfully.")
            return redirect('documents:detail', pk=document.id)
    else:
        form = DocumentEditForm(instance=document)

    return render(request, 'documents/document_edit.html', {'form': form, 'document': document})

@login_required
@require_POST
def document_replace_version_view(request, pk):
    """Upload a new version for an existing document."""
    document = get_object_or_404(Document, pk=pk)
    form = DocumentVersionReplaceForm(request.POST, request.FILES)
    if form.is_valid():
        try:
            replace_document_version(
                user=request.user,
                document=document,
                file_obj=request.FILES['file'],
                change_summary=form.cleaned_data.get('change_summary', ''),
                request=request
            )
            messages.success(request, f"New revision (v{document.version}) uploaded successfully.")
        except Exception as e:
            messages.error(request, f"Revision upload failed: {str(e)}")
    else:
        messages.error(request, "Invalid file submission for revision.")
    return redirect('documents:detail', pk=document.id)

@login_required
@require_POST
def document_delete_view(request, pk):
    """Soft-delete document (owner only)."""
    document = get_object_or_404(Document, pk=pk)
    try:
        soft_delete_document(request.user, document, request=request)
        messages.success(request, f"Document '{document.name}' has been soft-deleted.")
    except PermissionDenied as e:
        messages.error(request, str(e))
    return redirect('documents:list')

@login_required
@require_POST
def document_restore_view(request, pk):
    """Restore soft-deleted document (owner only)."""
    document = get_object_or_404(Document, pk=pk)
    try:
        restore_document(request.user, document, request=request)
        messages.success(request, f"Document '{document.name}' has been restored.")
    except PermissionDenied as e:
        messages.error(request, str(e))
    return redirect('documents:detail', pk=document.id)


# =====================================================================
# REST API Endpoints
# =====================================================================

class APIDocumentListCreateView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get(self, request):
        qs = get_accessible_documents_queryset(request.user)
        # Search filter
        q = request.query_params.get('q', '').strip()
        if q:
            qs = qs.filter(
                Q(name__icontains=q) |
                Q(description__icontains=q) |
                Q(tags__icontains=q)
            )
        category = request.query_params.get('category')
        if category:
            qs = qs.filter(category_id=category)

        serializer = DocumentDetailSerializer(qs, many=True)
        return Response(serializer.data)

    def post(self, request):
        if not (request.user.is_owner_role or request.user.is_admin_role):
            return Response(
                {"error": "Only Document Owners or Administrators can upload documents."},
                status=status.HTTP_403_FORBIDDEN
            )

        file_obj = request.FILES.get('file')
        if not file_obj:
            return Response({"error": "No file uploaded."}, status=status.HTTP_400_BAD_REQUEST)

        name = request.data.get('name', '')
        description = request.data.get('description', '')
        category_id = request.data.get('category')
        category = DocumentCategory.objects.filter(id=category_id).first() if category_id else None
        tags = request.data.get('tags', '')

        try:
            doc = upload_document(
                user=request.user,
                file_obj=file_obj,
                name=name,
                description=description,
                category=category,
                tags=tags,
                request=request
            )
            serializer = DocumentDetailSerializer(doc)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class APIDocumentDetailView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, pk, user, request):
        try:
            doc = Document.objects.select_related('owner', 'category').get(pk=pk)
        except (Document.DoesNotExist, ValueError):
            raise Http404("Document does not exist.")

        if not can_view_document(user, doc):
            record_audit_event(
                event_type=AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT,
                action_result=ActionResult.DENIED,
                actor=user,
                document_id=doc.id,
                document_name=doc.name,
                metadata={"action": "api_get_detail", "reason": "No active permission."},
                request=request
            )
            raise PermissionDenied("Access Denied: You do not have permission to view this document.")
        return doc

    def get(self, request, pk):
        doc = self.get_object(pk, request.user, request)
        record_audit_event(
            event_type=AuditEventType.DOCUMENT_VIEW,
            action_result=ActionResult.SUCCESS,
            actor=request.user,
            document_id=doc.id,
            document_name=doc.name,
            metadata={"channel": "API"},
            request=request
        )
        serializer = DocumentDetailSerializer(doc)
        return Response(serializer.data)

    def patch(self, request, pk):
        doc = self.get_object(pk, request.user, request)
        if not can_edit_document(request.user, doc):
            record_audit_event(
                event_type=AuditEventType.UNAUTHORIZED_MODIFICATION_ATTEMPT,
                action_result=ActionResult.DENIED,
                actor=request.user,
                document_id=doc.id,
                document_name=doc.name,
                metadata={"action": "api_patch_document"},
                request=request
            )
            return Response({"error": "You do not have permission to edit this document."}, status=status.HTTP_403_FORBIDDEN)

        serializer = DocumentDetailSerializer(doc, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            record_audit_event(
                event_type=AuditEventType.DOCUMENT_EDIT,
                action_result=ActionResult.SUCCESS,
                actor=request.user,
                document_id=doc.id,
                document_name=doc.name,
                metadata={"updated_fields": list(request.data.keys()), "channel": "API"},
                request=request
            )
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        try:
            doc = Document.objects.get(pk=pk)
        except Document.DoesNotExist:
            raise Http404("Document does not exist.")

        if not can_delete_document(request.user, doc):
            record_audit_event(
                event_type=AuditEventType.UNAUTHORIZED_MODIFICATION_ATTEMPT,
                action_result=ActionResult.DENIED,
                actor=request.user,
                document_id=doc.id,
                document_name=doc.name,
                metadata={"action": "api_delete_document"},
                request=request
            )
            return Response({"error": "Only the document owner can delete this document."}, status=status.HTTP_403_FORBIDDEN)

        soft_delete_document(request.user, doc, request=request)
        return Response({"message": "Document soft-deleted successfully."}, status=status.HTTP_200_OK)

class APIDocumentDownloadView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        try:
            doc = Document.objects.get(pk=pk)
        except (Document.DoesNotExist, ValueError):
            record_audit_event(
                event_type=AuditEventType.UNAUTHORIZED_DOWNLOAD_ATTEMPT,
                action_result=ActionResult.DENIED,
                actor=request.user,
                metadata={"reason": "Document ID not found (potential probing).", "requested_id": str(pk)},
                request=request
            )
            raise Http404("Document does not exist.")

        version_str = request.query_params.get('version')
        version_num = int(version_str) if version_str and version_str.isdigit() else None

        return serve_secure_file(request, doc, version_number=version_num)

class APIDocumentRestoreView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            doc = Document.objects.get(pk=pk)
        except Document.DoesNotExist:
            raise Http404("Document does not exist.")

        if not can_restore_document(request.user, doc):
            return Response({"error": "Only the document owner can restore this document."}, status=status.HTTP_403_FORBIDDEN)

        restore_document(request.user, doc, request=request)
        return Response({"message": "Document restored successfully."})

class APICategoryListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    queryset = DocumentCategory.objects.all()
    serializer_class = DocumentCategorySerializer
