import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

class PermissionType(models.TextChoices):
    READ = 'READ', _('Read & Download')
    EDIT = 'EDIT', _('Edit & Replace Version')

class DocumentPermission(models.Model):
    """
    Granular, document-level access grant.
    Guarantees:
      - Only document owners can grant or revoke.
      - At most ONE active permission grant exists per (document, user) pair.
      - Instant revocation: setting is_active=False blocks server-side access immediately.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    document = models.ForeignKey(
        'documents.Document',
        on_delete=models.CASCADE,
        related_name='permissions'
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='document_permissions'
    )
    permission_type = models.CharField(
        max_length=20,
        choices=PermissionType.choices,
        default=PermissionType.READ
    )
    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='granted_permissions'
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text=_('Active permissions grant current access. Inactive permissions are revoked.')
    )
    granted_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='revocations_performed'
    )

    class Meta:
        ordering = ['-granted_at']
        verbose_name = _('Document Permission')
        verbose_name_plural = _('Document Permissions')
        constraints = [
            models.UniqueConstraint(
                fields=['document', 'user'],
                condition=models.Q(is_active=True),
                name='unique_active_permission_per_doc_user'
            )
        ]
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['document', 'is_active']),
        ]

    def __str__(self):
        status = "Active" if self.is_active else "Revoked"
        return f"[{status}] {self.user.username} -> {self.document.name} ({self.get_permission_type_display()})"


class PermissionHistory(models.Model):
    """Immutable audit record of all permission state transitions."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    document = models.ForeignKey(
        'documents.Document',
        on_delete=models.CASCADE,
        related_name='permission_history'
    )
    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='permission_history_entries'
    )
    action = models.CharField(
        max_length=30,
        choices=[
            ('GRANTED', _('Granted')),
            ('CHANGED', _('Permission Level Changed')),
            ('REVOKED', _('Revoked')),
        ]
    )
    previous_type = models.CharField(max_length=20, blank=True)
    new_type = models.CharField(max_length=20, blank=True)
    performed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='permission_actions_performed'
    )
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = _('Permission History')
        verbose_name_plural = _('Permission Histories')

    def __str__(self):
        return f"{self.action} for {self.target_user.username} on {self.document.name} at {self.timestamp}"
