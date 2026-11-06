from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _

class UserRole(models.TextChoices):
    ADMIN = 'ADMIN', _('Administrator')
    OWNER = 'OWNER', _('Document Owner')
    VIEWER = 'VIEWER', _('Viewer')

class CustomUser(AbstractUser):
    """
    Custom user model with explicit Role-Based Access Control (RBAC).
    Three distinct roles:
      1. Administrator: System administration, audit monitoring, user lifecycle.
      2. Document Owner: Uploads, manages, grants and revokes permissions.
      3. Viewer: Reads and downloads permitted documents only.
    """
    role = models.CharField(
        max_length=20,
        choices=UserRole.choices,
        default=UserRole.VIEWER,
        help_text=_('Designates role-based permission tier in TrustVault.')
    )
    department = models.CharField(
        max_length=100,
        blank=True,
        help_text=_('Department or team within organization.')
    )
    email = models.EmailField(
        _('email address'),
        unique=True,
        error_messages={
            'unique': _('A user with that email already exists.'),
        }
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_('Designates whether this user account is active. Deactivated users cannot log in or access documents.')
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['username']
        verbose_name = _('User')
        verbose_name_plural = _('Users')
        indexes = [
            models.Index(fields=['role', 'is_active']),
            models.Index(fields=['email']),
        ]

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"

    @property
    def is_admin_role(self) -> bool:
        return self.role == UserRole.ADMIN

    @property
    def is_owner_role(self) -> bool:
        return self.role in (UserRole.OWNER, UserRole.ADMIN)

    @property
    def is_viewer_role(self) -> bool:
        return self.role == UserRole.VIEWER
