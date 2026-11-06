import hashlib
import os
from typing import Optional
from django.db import transaction
from django.db.models import Q
from django.conf import settings
from django.utils import timezone
from django.http import FileResponse, HttpResponseForbidden, Http404
from django.core.exceptions import PermissionDenied, ValidationError

from .models import Document, DocumentVersion, DocumentCategory
from .validators import validate_file_upload, sanitize_filename
from sharing.models import DocumentPermission, PermissionType
from audit.services import record_audit_event
from audit.models import AuditEventType, ActionResult

# =====================================================================
# Centralized Document Authorization Service
# =====================================================================

def can_view_document(user, document: Document) -> bool:
    """
    Check if user is authorized to view document metadata & details.
    - Owner can always view (including soft-deleted for restore).
    - Permitted users (active READ or EDIT grant) can view non-deleted documents.
    - Administrators can view metadata for compliance/monitoring.
    - Unauthorized users return False.
    """
    if not user or not user.is_authenticated or not user.is_active:
        return False

    if document.is_deleted:
        # Only the owner can view soft-deleted documents
        return document.owner_id == user.id

    if document.owner_id == user.id:
        return True

    # Check database-backed active permission
    has_perm = DocumentPermission.objects.filter(
        document=document,
        user=user,
        is_active=True
    ).exists()
    if has_perm:
        return True

    # Admin oversight: metadata visibility only
    if getattr(user, 'is_admin_role', False):
        return True

    return False

def can_download_document(user, document: Document) -> bool:
    """
    Check if user is authorized to download the document payload.
    - Confidentiality rule: Document owner or active READ/EDIT grant required.
    - Administrators DO NOT bypass document confidentiality by default.
    - Soft-deleted documents cannot be downloaded by anyone.
    """
    if not user or not user.is_authenticated or not user.is_active:
        return False

    if document.is_deleted:
        return False

    if document.owner_id == user.id:
        return True

    # Database check for active READ or EDIT grant
    return DocumentPermission.objects.filter(
        document=document,
        user=user,
        is_active=True,
        permission_type__in=[PermissionType.READ, PermissionType.EDIT]
    ).exists()

def can_edit_document(user, document: Document) -> bool:
    """
    Check if user is authorized to edit document metadata or replace versions.
    - Document owner can always edit.
    - Users with active EDIT grant can edit.
    - Read-only viewers, admins, and unauthorized users cannot edit.
    """
    if not user or not user.is_authenticated or not user.is_active:
        return False

    if document.is_deleted:
        return False

    if document.owner_id == user.id:
        return True

    return DocumentPermission.objects.filter(
        document=document,
        user=user,
        is_active=True,
        permission_type=PermissionType.EDIT
    ).exists()

def can_delete_document(user, document: Document) -> bool:
    """Only the document owner can delete their document."""
    if not user or not user.is_authenticated or not user.is_active:
        return False
    return document.owner_id == user.id

def can_manage_permissions(user, document: Document) -> bool:
    """Only the document owner can grant or revoke permissions."""
    if not user or not user.is_authenticated or not user.is_active:
        return False
    return document.owner_id == user.id

def can_restore_document(user, document: Document) -> bool:
    """Only the document owner can restore a soft-deleted document."""
    if not user or not user.is_authenticated or not user.is_active:
        return False
    return document.owner_id == user.id

def get_accessible_documents_queryset(user, include_deleted: bool = False):
    """
    Return queryset of documents the user is authorized to discover.
    Guarantees no search or list leaks of private unauthorized documents.
    """
    if not user or not user.is_authenticated or not user.is_active:
        return Document.objects.none()

    if getattr(user, 'is_admin_role', False):
        # Admin can oversee all documents metadata across the vault
        qs = Document.objects.all()
    else:
        # Regular users only see documents they own or have active permissions for
        qs = Document.objects.filter(
            Q(owner=user) |
            Q(permissions__user=user, permissions__is_active=True)
        ).distinct()

    if not include_deleted:
        qs = qs.filter(is_deleted=False)

    return qs.select_related('owner', 'category')


# =====================================================================
# Document Operations & File Lifecycle
# =====================================================================

def calculate_file_hash(file_obj) -> str:
    """Compute deterministic SHA-256 integrity hash of file contents."""
    sha = hashlib.sha256()
    file_obj.seek(0)
    for chunk in file_obj.chunks(4096):
        sha.update(chunk)
    file_obj.seek(0)
    return sha.hexdigest()

def upload_document(
    user,
    file_obj,
    name: str,
    description: str = "",
    category: Optional[DocumentCategory] = None,
    tags: str = "",
    request=None
) -> Document:
    """
    Upload a new confidential document into private storage.
    Performs full validation, hashing, initial version creation, and audit logging.
    """
    if not user or not user.is_authenticated or not user.is_active:
        raise PermissionDenied("Authentication required to upload documents.")

    # Validate file security properties
    validate_file_upload(file_obj)

    clean_filename = sanitize_filename(file_obj.name)
    _, ext = os.path.splitext(clean_filename)
    file_hash = calculate_file_hash(file_obj)
    file_size = file_obj.size

    # Detect MIME type
    import filetype
    kind = filetype.guess(file_obj.read(1024))
    file_obj.seek(0)
    mime_type = kind.mime if kind else ('text/plain' if ext == '.txt' else 'application/octet-stream')

    with transaction.atomic():
        doc = Document(
            name=name.strip() or clean_filename,
            description=description.strip(),
            category=category,
            tags=tags.strip(),
            original_filename=clean_filename,
            file_type=mime_type,
            file_extension=ext.lower(),
            file_size=file_size,
            file_hash=file_hash,
            owner=user,
            version=1
        )
        doc.file.save(clean_filename, file_obj, save=False)
        doc.save()

        # Archive version 1
        DocumentVersion.objects.create(
            document=doc,
            version_number=1,
            file=doc.file,
            original_filename=clean_filename,
            file_size=file_size,
            file_hash=file_hash,
            uploaded_by=user,
            change_summary="Initial document upload."
        )

        record_audit_event(
            event_type=AuditEventType.DOCUMENT_UPLOAD,
            action_result=ActionResult.SUCCESS,
            actor=user,
            document_id=doc.id,
            document_name=doc.name,
            metadata={
                "filename": clean_filename,
                "file_size": file_size,
                "file_hash": file_hash,
                "category": category.name if category else None
            },
            request=request
        )

    return doc

def replace_document_version(
    user,
    document: Document,
    file_obj,
    change_summary: str = "",
    request=None
) -> DocumentVersion:
    """
    Upload a replacement version for an existing document.
    Requires EDIT permission or Ownership.
    """
    if not can_edit_document(user, document):
        record_audit_event(
            event_type=AuditEventType.UNAUTHORIZED_MODIFICATION_ATTEMPT,
            action_result=ActionResult.DENIED,
            actor=user,
            document_id=document.id,
            document_name=document.name,
            metadata={"action": "replace_version", "reason": "Insufficient permission to replace version."},
            request=request
        )
        raise PermissionDenied("You do not have permission to upload new versions of this document.")

    validate_file_upload(file_obj)

    clean_filename = sanitize_filename(file_obj.name)
    _, ext = os.path.splitext(clean_filename)
    file_hash = calculate_file_hash(file_obj)
    file_size = file_obj.size

    import filetype
    kind = filetype.guess(file_obj.read(1024))
    file_obj.seek(0)
    mime_type = kind.mime if kind else ('text/plain' if ext == '.txt' else 'application/octet-stream')

    with transaction.atomic():
        new_version_num = document.version + 1
        document.version = new_version_num
        document.original_filename = clean_filename
        document.file_type = mime_type
        document.file_extension = ext.lower()
        document.file_size = file_size
        document.file_hash = file_hash

        # Save new primary file
        document.file.save(clean_filename, file_obj, save=False)
        document.save()

        version_obj = DocumentVersion.objects.create(
            document=document,
            version_number=new_version_num,
            file=document.file,
            original_filename=clean_filename,
            file_size=file_size,
            file_hash=file_hash,
            uploaded_by=user,
            change_summary=change_summary.strip() or f"Updated to version {new_version_num}."
        )

        record_audit_event(
            event_type=AuditEventType.DOCUMENT_VERSION_REPLACE,
            action_result=ActionResult.SUCCESS,
            actor=user,
            document_id=document.id,
            document_name=document.name,
            metadata={
                "new_version": new_version_num,
                "filename": clean_filename,
                "file_size": file_size,
                "file_hash": file_hash,
                "change_summary": change_summary
            },
            request=request
        )

    return version_obj

def soft_delete_document(user, document: Document, request=None) -> bool:
    """Soft-delete a document with audit logging. Retention policy permits owner recovery."""
    if not can_delete_document(user, document):
        record_audit_event(
            event_type=AuditEventType.UNAUTHORIZED_MODIFICATION_ATTEMPT,
            action_result=ActionResult.DENIED,
            actor=user,
            document_id=document.id,
            document_name=document.name,
            metadata={"action": "delete_document", "reason": "Only owner can delete document."},
            request=request
        )
        raise PermissionDenied("Only the document owner can delete this document.")

    with transaction.atomic():
        document.is_deleted = True
        document.deleted_at = timezone.now()
        document.deleted_by = user
        document.save()

        record_audit_event(
            event_type=AuditEventType.DOCUMENT_DELETE,
            action_result=ActionResult.SUCCESS,
            actor=user,
            document_id=document.id,
            document_name=document.name,
            metadata={"deleted_at": document.deleted_at.isoformat()},
            request=request
        )
    return True

def restore_document(user, document: Document, request=None) -> bool:
    """Restore a soft-deleted document."""
    if not can_restore_document(user, document):
        record_audit_event(
            event_type=AuditEventType.UNAUTHORIZED_MODIFICATION_ATTEMPT,
            action_result=ActionResult.DENIED,
            actor=user,
            document_id=document.id,
            document_name=document.name,
            metadata={"action": "restore_document", "reason": "Only owner can restore document."},
            request=request
        )
        raise PermissionDenied("Only the document owner can restore this document.")

    with transaction.atomic():
        document.is_deleted = False
        document.deleted_at = None
        document.deleted_by = None
        document.save()

        record_audit_event(
            event_type=AuditEventType.DOCUMENT_RESTORE,
            action_result=ActionResult.SUCCESS,
            actor=user,
            document_id=document.id,
            document_name=document.name,
            request=request
        )
    return True

def serve_secure_file(request, document: Document, version_number: Optional[int] = None):
    """
    Dedicated secure document download service.
    Features:
      1. Rechecks current database authorization on every request.
      2. Logs unauthorized download attempts (DENIED).
      3. Logs successful downloads (SUCCESS).
      4. Sets hardened security response headers.
      5. Never exposes storage path or static URLs.
    """
    user = request.user if request and hasattr(request, 'user') else None

    # Step 1: Authorization Check
    if not can_download_document(user, document):
        record_audit_event(
            event_type=AuditEventType.UNAUTHORIZED_DOWNLOAD_ATTEMPT,
            action_result=ActionResult.DENIED,
            actor=user,
            document_id=document.id,
            document_name=document.name,
            metadata={
                "requested_version": version_number,
                "reason": "User lacks active download authorization."
            },
            request=request
        )
        # Return HTTP 403 Forbidden
        return HttpResponseForbidden(
            "Access Denied: You do not have active authorization to download this confidential document."
        )

    # Step 2: Determine file target (primary document or historical version)
    if version_number and version_number != document.version:
        version_obj = document.versions.filter(version_number=version_number).first()
        if not version_obj:
            raise Http404("Document version not found.")
        target_file = version_obj.file
        download_name = version_obj.original_filename
        file_hash = version_obj.file_hash
    else:
        target_file = document.file
        download_name = document.original_filename
        file_hash = document.file_hash

    if not target_file:
        raise Http404("Document file payload unavailable.")

    # Step 3: Record Successful Download in Tamper-Evident Audit Trail
    record_audit_event(
        event_type=AuditEventType.DOCUMENT_DOWNLOAD,
        action_result=ActionResult.SUCCESS,
        actor=user,
        document_id=document.id,
        document_name=document.name,
        metadata={
            "version": version_number or document.version,
            "filename": download_name,
            "file_hash": file_hash
        },
        request=request
    )

    # Step 4: Stream Secure File Response with Hardened Headers
    response = FileResponse(
        target_file.open('rb'),
        content_type=document.file_type or 'application/octet-stream',
        as_attachment=True,
        filename=download_name
    )

    # Hardened HTTP Headers
    response['X-Content-Type-Options'] = 'nosniff'
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'

    return response
