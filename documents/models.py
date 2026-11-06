import os
import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from .storage import private_storage

def document_upload_path(instance, filename):
    """Generate isolated, non-predictable storage path for primary document file."""
    ext = os.path.splitext(filename)[1].lower()
    return f"vault_docs/{instance.id}/{uuid.uuid4().hex}{ext}"

def version_upload_path(instance, filename):
    """Generate isolated storage path for document version archive."""
    ext = os.path.splitext(filename)[1].lower()
    return f"vault_docs/{instance.document.id}/v{instance.version_number}_{uuid.uuid4().hex}{ext}"

class DocumentCategory(models.Model):
    """Categories for organizing enterprise documents."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=120, unique=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['name']
        verbose_name = _('Document Category')
        verbose_name_plural = _('Document Categories')

    def __str__(self):
        return self.name

class Document(models.Model):
    """
    Core document model.
    Files are stored in private storage (never public media).
    Access is strictly checked through centralized authorization on every request.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, db_index=True)
    description = models.TextField(blank=True)
    category = models.ForeignKey(
        DocumentCategory,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='documents'
    )
    tags = models.CharField(
        max_length=255,
        blank=True,
        help_text=_('Comma-separated search tags.')
    )

    # Secure File Properties
    file = models.FileField(
        storage=private_storage,
        upload_to=document_upload_path
    )
    original_filename = models.CharField(max_length=255)
    file_type = models.CharField(max_length=100)
    file_extension = models.CharField(max_length=20)
    file_size = models.BigIntegerField(help_text=_('File size in bytes'))
    file_hash = models.CharField(
        max_length=64,
        help_text=_('SHA-256 integrity hash of document content.')
    )

    # Ownership & Versioning
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='owned_documents'
    )
    version = models.PositiveIntegerField(default=1)

    # Soft Delete for Retention & Recovery
    is_deleted = models.BooleanField(default=False, db_index=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='deleted_documents'
    )

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = _('Document')
        verbose_name_plural = _('Documents')
        indexes = [
            models.Index(fields=['owner', 'is_deleted']),
            models.Index(fields=['category', 'is_deleted']),
            models.Index(fields=['created_at', 'is_deleted']),
        ]

    def __str__(self):
        return f"{self.name} (v{self.version}) - {self.owner.username}"

    @property
    def formatted_size(self) -> str:
        """Format file size in human-readable units."""
        bytes_val = self.file_size
        if bytes_val < 1024:
            return f"{bytes_val} B"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val / 1024:.1f} KB"
        else:
            return f"{bytes_val / (1024 * 1024):.2f} MB"

    @property
    def tag_list(self):
        if not self.tags:
            return []
        return [t.strip() for t in self.tags.split(',') if t.strip()]


class DocumentVersion(models.Model):
    """Historical versions of a document with cryptographic integrity hashes."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    document = models.ForeignKey(
        Document,
        on_delete=models.CASCADE,
        related_name='versions'
    )
    version_number = models.PositiveIntegerField()
    file = models.FileField(
        storage=private_storage,
        upload_to=version_upload_path
    )
    original_filename = models.CharField(max_length=255)
    file_size = models.BigIntegerField()
    file_hash = models.CharField(max_length=64)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='uploaded_versions'
    )
    change_summary = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-version_number']
        unique_together = ('document', 'version_number')
        verbose_name = _('Document Version')
        verbose_name_plural = _('Document Versions')

    def __str__(self):
        return f"{self.document.name} v{self.version_number}"

    @property
    def formatted_size(self) -> str:
        bytes_val = self.file_size
        if bytes_val < 1024:
            return f"{bytes_val} B"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val / 1024:.1f} KB"
        else:
            return f"{bytes_val / (1024 * 1024):.2f} MB"
