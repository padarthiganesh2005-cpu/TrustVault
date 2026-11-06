import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.core.exceptions import PermissionDenied
from django.utils.translation import gettext_lazy as _

class AuditEventType(models.TextChoices):
    # Authentication & Identity Events
    USER_LOGIN = 'USER_LOGIN', _('User Login')
    USER_LOGIN_FAILED = 'USER_LOGIN_FAILED', _('User Login Failed')
    USER_LOGOUT = 'USER_LOGOUT', _('User Logout')
    USER_REGISTERED = 'USER_REGISTERED', _('User Registered')
    USER_ACTIVATED = 'USER_ACTIVATED', _('User Activated')
    USER_DEACTIVATED = 'USER_DEACTIVATED', _('User Deactivated')

    # Document Lifecycle Events
    DOCUMENT_UPLOAD = 'DOCUMENT_UPLOAD', _('Document Upload')
    DOCUMENT_VIEW = 'DOCUMENT_VIEW', _('Document View')
    DOCUMENT_DOWNLOAD = 'DOCUMENT_DOWNLOAD', _('Document Download')
    DOCUMENT_EDIT = 'DOCUMENT_EDIT', _('Document Edit')
    DOCUMENT_VERSION_REPLACE = 'DOCUMENT_VERSION_REPLACE', _('Document Version Replace')
    DOCUMENT_DELETE = 'DOCUMENT_DELETE', _('Document Delete')
    DOCUMENT_RESTORE = 'DOCUMENT_RESTORE', _('Document Restore')

    # Permission & Access Control Events
    PERMISSION_GRANTED = 'PERMISSION_GRANTED', _('Permission Granted')
    PERMISSION_CHANGED = 'PERMISSION_CHANGED', _('Permission Changed')
    PERMISSION_REVOKED = 'PERMISSION_REVOKED', _('Permission Revoked')

    # Security & Unauthorized Events
    UNAUTHORIZED_ACCESS_ATTEMPT = 'UNAUTHORIZED_ACCESS_ATTEMPT', _('Unauthorized Document Access Attempt')
    UNAUTHORIZED_DOWNLOAD_ATTEMPT = 'UNAUTHORIZED_DOWNLOAD_ATTEMPT', _('Unauthorized Download Attempt')
    UNAUTHORIZED_MODIFICATION_ATTEMPT = 'UNAUTHORIZED_MODIFICATION_ATTEMPT', _('Unauthorized Modification Attempt')
    ADMIN_ACTION = 'ADMIN_ACTION', _('Administrative Action')
    BREAK_GLASS_ACCESS = 'BREAK_GLASS_ACCESS', _('Break-Glass Emergency Access')

class ActionResult(models.TextChoices):
    SUCCESS = 'SUCCESS', _('Success')
    DENIED = 'DENIED', _('Denied')

class AuditLog(models.Model):
    """
    Append-only, cryptographically hash-chained audit record.
    Each record binds:
      current_hash = SHA256(previous_hash + canonical_event_data)
    Direct updates and deletions are strictly blocked at model and database layers.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sequence_number = models.BigIntegerField(unique=True, db_index=True)

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='audit_records'
    )
    actor_username = models.CharField(max_length=150, db_index=True)
    actor_role = models.CharField(max_length=50, blank=True)

    event_type = models.CharField(
        max_length=60,
        choices=AuditEventType.choices,
        db_index=True
    )
    document_id = models.UUIDField(null=True, blank=True, db_index=True)
    document_name = models.CharField(max_length=255, blank=True)

    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='targeted_audit_records'
    )
    target_username = models.CharField(max_length=150, blank=True)

    action_result = models.CharField(
        max_length=20,
        choices=ActionResult.choices,
        default=ActionResult.SUCCESS,
        db_index=True
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)

    # Cryptographic Hash Chain Fields
    previous_hash = models.CharField(max_length=64)
    current_hash = models.CharField(max_length=64, db_index=True)

    class Meta:
        ordering = ['-sequence_number']
        verbose_name = _('Audit Log')
        verbose_name_plural = _('Audit Logs')
        indexes = [
            models.Index(fields=['document_id', 'timestamp']),
            models.Index(fields=['actor_username', 'timestamp']),
            models.Index(fields=['event_type', 'action_result']),
        ]

    def __str__(self):
        return f"Audit #{self.sequence_number} [{self.event_type}] - {self.action_result} by {self.actor_username}"

    def save(self, *args, **kwargs):
        # Enforce append-only semantics: cannot update existing record
        if not self._state.adding and AuditLog.objects.filter(pk=self.pk).exists():
            raise PermissionDenied("Audit records are strictly append-only and cannot be modified.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        # Enforce immutability: cannot delete audit records
        raise PermissionDenied("Audit records are permanent and cannot be deleted.")


class SecurityEvent(models.Model):
    """
    High-priority security alerts generated when unauthorized attempts,
    brute-force patterns, or abnormal permission anomalies are detected.
    """
    SEVERITY_CHOICES = [
        ('LOW', _('Low')),
        ('MEDIUM', _('Medium')),
        ('HIGH', _('High')),
        ('CRITICAL', _('Critical')),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_type = models.CharField(max_length=100, db_index=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='MEDIUM')
    actor_username = models.CharField(max_length=150, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    description = models.TextField()
    details = models.JSONField(default=dict, blank=True)
    is_resolved = models.BooleanField(default=False)
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='resolved_security_events'
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = _('Security Event')
        verbose_name_plural = _('Security Events')

    def __str__(self):
        return f"[{self.severity}] {self.event_type} - {self.description[:50]}"
