from django.test import TestCase
from django.core.files.base import ContentFile
from django.core.exceptions import PermissionDenied, ValidationError
from accounts.models import CustomUser, UserRole
from documents.models import Document
from documents.services import upload_document
from sharing.models import DocumentPermission, PermissionType
from sharing.services import (
    grant_document_permission,
    update_permission_level,
    revoke_document_permission,
    has_active_document_permission
)

class SharingAndImmediateRevocationTests(TestCase):
    def setUp(self):
        self.owner = CustomUser.objects.create_user(
            username='owner_user',
            email='owner@vault.local',
            password='Password123!@#',
            role=UserRole.OWNER
        )
        self.viewer = CustomUser.objects.create_user(
            username='viewer_user',
            email='viewer@vault.local',
            password='Password123!@#',
            role=UserRole.VIEWER
        )
        self.attacker = CustomUser.objects.create_user(
            username='attacker_user',
            email='attacker@vault.local',
            password='Password123!@#',
            role=UserRole.VIEWER
        )
        pdf = ContentFile(b"%PDF-1.4\nSecret Financial Ledger", name="ledger.pdf")
        self.doc = upload_document(self.owner, pdf, name="Ledger")

    def test_owner_can_grant_and_update_permissions(self):
        perm = grant_document_permission(self.owner, self.doc, self.viewer, PermissionType.READ)
        self.assertTrue(perm.is_active)
        self.assertEqual(perm.permission_type, PermissionType.READ)
        self.assertTrue(has_active_document_permission(self.viewer, self.doc, PermissionType.READ))
        self.assertFalse(has_active_document_permission(self.viewer, self.doc, PermissionType.EDIT))

        # Elevate to EDIT
        perm = update_permission_level(self.owner, perm, PermissionType.EDIT)
        self.assertEqual(perm.permission_type, PermissionType.EDIT)
        self.assertTrue(has_active_document_permission(self.viewer, self.doc, PermissionType.EDIT))

    def test_non_owner_cannot_grant_permission(self):
        with self.assertRaises(PermissionDenied):
            grant_document_permission(self.attacker, self.doc, self.attacker, PermissionType.READ)

    def test_immediate_revocation(self):
        perm = grant_document_permission(self.owner, self.doc, self.viewer, PermissionType.READ)
        self.assertTrue(has_active_document_permission(self.viewer, self.doc))

        # Revoke access
        revoke_document_permission(self.owner, perm)
        perm.refresh_from_db()
        self.assertFalse(perm.is_active)

        # Immediate DB check must return False
        self.assertFalse(has_active_document_permission(self.viewer, self.doc))

    def test_cannot_grant_to_deactivated_user(self):
        self.viewer.is_active = False
        self.viewer.save()
        with self.assertRaises(ValidationError):
            grant_document_permission(self.owner, self.doc, self.viewer, PermissionType.READ)
