from typing import Optional
from django.db import transaction
from django.utils import timezone
from django.core.exceptions import PermissionDenied, ValidationError
from .models import DocumentPermission, PermissionHistory, PermissionType
from audit.services import record_audit_event
from audit.models import AuditEventType, ActionResult

def has_active_document_permission(user, document, required_type: Optional[str] = None) -> bool:
    """
    Direct, zero-cache database check of active permission.
    Guarantees that access revocation takes effect immediately.
    """
    if not user or not user.is_authenticated or not user.is_active:
        return False

    # Document owner always has full authorization
    if document.owner_id == user.id:
        return True

    # Confidentiality barrier: Administrators DO NOT get automatic document content access!
    # They only have system oversight unless explicitly granted permission by the owner.

    qs = DocumentPermission.objects.filter(
        document=document,
        user=user,
        is_active=True
    )

    if required_type == PermissionType.EDIT:
        return qs.filter(permission_type=PermissionType.EDIT).exists()
    elif required_type in (PermissionType.READ, None):
        return qs.filter(permission_type__in=[PermissionType.READ, PermissionType.EDIT]).exists()

    return False

def grant_document_permission(granter, document, target_user, permission_type: str) -> DocumentPermission:
    """
    Grant access to a target user.
    Rules:
      - Only the document owner can grant permissions.
      - Granter cannot grant to themselves.
      - Target user must be active.
      - Prevents duplicate active grants using database transactions and constraints.
    """
    if not granter or not granter.is_authenticated:
        raise PermissionDenied("Authentication required.")

    if document.owner_id != granter.id:
        # Denied attempt logging
        record_audit_event(
            event_type=AuditEventType.UNAUTHORIZED_MODIFICATION_ATTEMPT,
            action_result=ActionResult.DENIED,
            actor=granter,
            document_id=document.id,
            document_name=document.name,
            target_user=target_user,
            metadata={"action": "grant_permission", "reason": "Actor is not document owner."}
        )
        raise PermissionDenied("Only the document owner can grant permissions.")

    if target_user.id == granter.id:
        raise ValidationError("Document owner inherently owns the document; granting to self is redundant.")

    if not target_user.is_active:
        raise ValidationError("Cannot grant permissions to an inactive or deactivated user account.")

    if permission_type not in PermissionType.values:
        raise ValidationError(f"Invalid permission type '{permission_type}'.")

    with transaction.atomic():
        # Check for existing active permission with row locking
        existing = DocumentPermission.objects.select_for_update().filter(
            document=document,
            user=target_user,
            is_active=True
        ).first()

        if existing:
            if existing.permission_type == permission_type:
                return existing
            # If changing type, transition it
            prev_type = existing.permission_type
            existing.permission_type = permission_type
            existing.save()

            PermissionHistory.objects.create(
                document=document,
                target_user=target_user,
                action='CHANGED',
                previous_type=prev_type,
                new_type=permission_type,
                performed_by=granter,
                notes=f"Changed permission from {prev_type} to {permission_type}."
            )

            record_audit_event(
                event_type=AuditEventType.PERMISSION_CHANGED,
                action_result=ActionResult.SUCCESS,
                actor=granter,
                document_id=document.id,
                document_name=document.name,
                target_user=target_user,
                metadata={
                    "previous_type": prev_type,
                    "new_type": permission_type,
                    "permission_id": str(existing.id)
                }
            )
            return existing

        # Create new grant
        permission = DocumentPermission.objects.create(
            document=document,
            user=target_user,
            permission_type=permission_type,
            granted_by=granter,
            is_active=True
        )

        PermissionHistory.objects.create(
            document=document,
            target_user=target_user,
            action='GRANTED',
            previous_type='',
            new_type=permission_type,
            performed_by=granter,
            notes=f"Granted {permission_type} permission."
        )

        record_audit_event(
            event_type=AuditEventType.PERMISSION_GRANTED,
            action_result=ActionResult.SUCCESS,
            actor=granter,
            document_id=document.id,
            document_name=document.name,
            target_user=target_user,
            metadata={
                "permission_type": permission_type,
                "permission_id": str(permission.id)
            }
        )
        return permission

def update_permission_level(updater, permission: DocumentPermission, new_type: str) -> DocumentPermission:
    """Update permission type (READ <-> EDIT) by document owner."""
    if document_owner_id := permission.document.owner_id:
        if updater.id != document_owner_id:
            record_audit_event(
                event_type=AuditEventType.UNAUTHORIZED_MODIFICATION_ATTEMPT,
                action_result=ActionResult.DENIED,
                actor=updater,
                document_id=permission.document.id,
                document_name=permission.document.name,
                target_user=permission.user,
                metadata={"action": "update_permission_level", "reason": "Actor is not document owner."}
            )
            raise PermissionDenied("Only the document owner can modify permissions.")

    if not permission.is_active:
        raise ValidationError("Cannot modify a revoked permission. Issue a new grant instead.")

    if new_type not in PermissionType.values:
        raise ValidationError(f"Invalid permission type '{new_type}'.")

    if permission.permission_type == new_type:
        return permission

    prev_type = permission.permission_type
    with transaction.atomic():
        permission.permission_type = new_type
        permission.save()

        PermissionHistory.objects.create(
            document=permission.document,
            target_user=permission.user,
            action='CHANGED',
            previous_type=prev_type,
            new_type=new_type,
            performed_by=updater,
            notes=f"Changed permission from {prev_type} to {new_type}."
        )

        record_audit_event(
            event_type=AuditEventType.PERMISSION_CHANGED,
            action_result=ActionResult.SUCCESS,
            actor=updater,
            document_id=permission.document.id,
            document_name=permission.document.name,
            target_user=permission.user,
            metadata={
                "previous_type": prev_type,
                "new_type": new_type,
                "permission_id": str(permission.id)
            }
        )
    return permission

def revoke_document_permission(revoker, permission: DocumentPermission) -> bool:
    """
    Immediately revoke a document permission.
    Rules:
      - Only document owner can revoke.
      - Sets is_active=False and marks revocation timestamp.
      - Records audit trail event and permission history.
      - Access stops working immediately on subsequent requests.
    """
    if not revoker or not revoker.is_authenticated:
        raise PermissionDenied("Authentication required.")

    if permission.document.owner_id != revoker.id:
        record_audit_event(
            event_type=AuditEventType.UNAUTHORIZED_MODIFICATION_ATTEMPT,
            action_result=ActionResult.DENIED,
            actor=revoker,
            document_id=permission.document.id,
            document_name=permission.document.name,
            target_user=permission.user,
            metadata={"action": "revoke_permission", "reason": "Actor is not document owner."}
        )
        raise PermissionDenied("Only the document owner can revoke permissions.")

    if not permission.is_active:
        return True  # Already revoked

    with transaction.atomic():
        permission.is_active = False
        permission.revoked_at = timezone.now()
        permission.revoked_by = revoker
        permission.save()

        PermissionHistory.objects.create(
            document=permission.document,
            target_user=permission.user,
            action='REVOKED',
            previous_type=permission.permission_type,
            new_type='',
            performed_by=revoker,
            notes=f"Revoked {permission.permission_type} permission."
        )

        record_audit_event(
            event_type=AuditEventType.PERMISSION_REVOKED,
            action_result=ActionResult.SUCCESS,
            actor=revoker,
            document_id=permission.document.id,
            document_name=permission.document.name,
            target_user=permission.user,
            metadata={
                "revoked_permission_type": permission.permission_type,
                "permission_id": str(permission.id)
            }
        )
    return True
