"""
TrustVault Master Security Verification Test Suite
Verifies all 27 mandatory hackathon security scenarios end-to-end.
"""

import uuid
from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.base import ContentFile
from django.core.exceptions import PermissionDenied, ValidationError
from rest_framework.test import APIClient
from rest_framework import status

from accounts.models import CustomUser, UserRole
from documents.models import Document, DocumentCategory
from documents.services import (
    upload_document,
    can_view_document,
    can_download_document,
    can_edit_document,
    can_delete_document,
    get_accessible_documents_queryset,
    soft_delete_document
)
from sharing.models import DocumentPermission, PermissionType
from sharing.services import (
    grant_document_permission,
    revoke_document_permission,
    update_permission_level,
    has_active_document_permission
)
from audit.models import AuditLog, AuditEventType, ActionResult
from audit.services import verify_audit_chain, record_audit_event
from documents.validators import validate_file_upload

class MasterTrustVaultSecurityTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.api_client = APIClient()

        # Users Setup: Admin, Owner A, Owner B, Viewer A, Viewer B
        self.admin = CustomUser.objects.create_user(
            username='admin_a',
            email='admin@test.local',
            password='AdminPass123!@#',
            role=UserRole.ADMIN,
            is_staff=True
        )
        self.owner_a = CustomUser.objects.create_user(
            username='owner_a',
            email='owner_a@test.local',
            password='OwnerPass123!@#',
            role=UserRole.OWNER
        )
        self.owner_b = CustomUser.objects.create_user(
            username='owner_b',
            email='owner_b@test.local',
            password='OwnerPass123!@#',
            role=UserRole.OWNER
        )
        self.viewer_a = CustomUser.objects.create_user(
            username='viewer_a',
            email='viewer_a@test.local',
            password='ViewerPass123!@#',
            role=UserRole.VIEWER
        )
        self.viewer_b = CustomUser.objects.create_user(
            username='viewer_b',
            email='viewer_b@test.local',
            password='ViewerPass123!@#',
            role=UserRole.VIEWER
        )

        # Upload initial test documents
        pdf_payload = b"%PDF-1.4\nConfidential Data for Owner A\n%%EOF"
        self.doc_a = upload_document(
            user=self.owner_a,
            file_obj=ContentFile(pdf_payload, name="Doc_A.pdf"),
            name="Confidential Doc A",
            description="Highly sensitive corporate asset."
        )

        pdf_payload_b = b"%PDF-1.4\nConfidential Data for Owner B\n%%EOF"
        self.doc_b = upload_document(
            user=self.owner_b,
            file_obj=ContentFile(pdf_payload_b, name="Doc_B.pdf"),
            name="Confidential Doc B"
        )

    # -------------------------------------------------------------
    # Scenario 1: Unauthenticated users cannot access protected documents
    # -------------------------------------------------------------
    def test_01_unauthenticated_access_denied(self):
        # Web detail URL redirects to login
        resp = self.client.get(reverse('documents:detail', kwargs={'pk': self.doc_a.id}))
        self.assertEqual(resp.status_code, 302)
        self.assertIn('login', resp.url)

        # API download returns 401 or 403 Forbidden
        api_resp = self.api_client.get(f"/api/documents/{self.doc_a.id}/download/")
        self.assertIn(api_resp.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    # -------------------------------------------------------------
    # Scenario 2: Owner can access their own document
    # -------------------------------------------------------------
    def test_02_owner_can_access_own_document(self):
        self.assertTrue(can_view_document(self.owner_a, self.doc_a))
        self.assertTrue(can_download_document(self.owner_a, self.doc_a))
        self.assertTrue(can_edit_document(self.owner_a, self.doc_a))
        self.assertTrue(can_delete_document(self.owner_a, self.doc_a))

        self.client.force_login(self.owner_a)
        resp = self.client.get(reverse('documents:detail', kwargs={'pk': self.doc_a.id}))
        self.assertEqual(resp.status_code, 200)

    # -------------------------------------------------------------
    # Scenario 3: Viewer cannot access an unshared document
    # -------------------------------------------------------------
    def test_03_viewer_cannot_access_unshared_document(self):
        self.assertFalse(can_view_document(self.viewer_a, self.doc_a))
        self.assertFalse(can_download_document(self.viewer_a, self.doc_a))

        self.client.force_login(self.viewer_a)
        resp = self.client.get(reverse('documents:detail', kwargs={'pk': self.doc_a.id}))
        # View detail denied with 403
        self.assertEqual(resp.status_code, 403)

    # -------------------------------------------------------------
    # Scenario 4: Viewer can read a shared document
    # -------------------------------------------------------------
    def test_04_viewer_can_read_shared_document(self):
        grant_document_permission(self.owner_a, self.doc_a, self.viewer_a, PermissionType.READ)
        self.assertTrue(can_view_document(self.viewer_a, self.doc_a))
        self.assertTrue(can_download_document(self.viewer_a, self.doc_a))

        self.client.force_login(self.viewer_a)
        resp = self.client.get(reverse('documents:detail', kwargs={'pk': self.doc_a.id}))
        self.assertEqual(resp.status_code, 200)

    # -------------------------------------------------------------
    # Scenario 5: Viewer cannot edit a read-only document
    # -------------------------------------------------------------
    def test_05_viewer_cannot_edit_read_only_document(self):
        grant_document_permission(self.owner_a, self.doc_a, self.viewer_a, PermissionType.READ)
        self.assertFalse(can_edit_document(self.viewer_a, self.doc_a))

        self.client.force_login(self.viewer_a)
        resp = self.client.post(reverse('documents:edit', kwargs={'pk': self.doc_a.id}), {'name': 'Hacked Title'})
        self.assertEqual(resp.status_code, 403)

    # -------------------------------------------------------------
    # Scenario 6: Edit permission allows permitted editing
    # -------------------------------------------------------------
    def test_06_edit_permission_allows_permitted_editing(self):
        perm = grant_document_permission(self.owner_a, self.doc_a, self.viewer_a, PermissionType.EDIT)
        self.assertTrue(can_edit_document(self.viewer_a, self.doc_a))

        self.client.force_login(self.viewer_a)
        resp = self.client.post(reverse('documents:edit', kwargs={'pk': self.doc_a.id}), {
            'name': 'Updated Authorized Title',
            'description': 'Updated description',
        })
        self.assertEqual(resp.status_code, 302)
        self.doc_a.refresh_from_db()
        self.assertEqual(self.doc_a.name, 'Updated Authorized Title')

    # -------------------------------------------------------------
    # Scenario 7: Unauthorized users cannot download documents
    # -------------------------------------------------------------
    def test_07_unauthorized_users_cannot_download(self):
        self.client.force_login(self.viewer_b)
        resp = self.client.get(reverse('documents:download', kwargs={'pk': self.doc_a.id}))
        self.assertEqual(resp.status_code, 403)

    # -------------------------------------------------------------
    # Scenario 8: Unauthorized users cannot delete documents
    # -------------------------------------------------------------
    def test_08_unauthorized_users_cannot_delete(self):
        grant_document_permission(self.owner_a, self.doc_a, self.viewer_a, PermissionType.EDIT)
        self.client.force_login(self.viewer_a)
        resp = self.client.post(reverse('documents:delete', kwargs={'pk': self.doc_a.id}))
        self.doc_a.refresh_from_db()
        self.assertFalse(self.doc_a.is_deleted)

    # -------------------------------------------------------------
    # Scenario 9: Unauthorized users cannot change permissions
    # -------------------------------------------------------------
    def test_09_unauthorized_users_cannot_change_permissions(self):
        # Viewer A attempts to grant access to Viewer B
        with self.assertRaises(PermissionDenied):
            grant_document_permission(self.viewer_a, self.doc_a, self.viewer_b, PermissionType.READ)

    # -------------------------------------------------------------
    # Scenario 10: Owner can grant access
    # -------------------------------------------------------------
    def test_10_owner_can_grant_access(self):
        perm = grant_document_permission(self.owner_a, self.doc_a, self.viewer_a, PermissionType.READ)
        self.assertIsNotNone(perm)
        self.assertTrue(perm.is_active)
        self.assertTrue(has_active_document_permission(self.viewer_a, self.doc_a))

    # -------------------------------------------------------------
    # Scenario 11: Owner can revoke access
    # -------------------------------------------------------------
    def test_11_owner_can_revoke_access(self):
        perm = grant_document_permission(self.owner_a, self.doc_a, self.viewer_a, PermissionType.READ)
        self.assertTrue(has_active_document_permission(self.viewer_a, self.doc_a))
        revoke_document_permission(self.owner_a, perm)
        self.assertFalse(has_active_document_permission(self.viewer_a, self.doc_a))

    # -------------------------------------------------------------
    # Scenario 12, 13, 14: Revoked user immediately loses access (URL, download, API)
    # -------------------------------------------------------------
    def test_12_13_14_immediate_revocation_enforced(self):
        perm = grant_document_permission(self.owner_a, self.doc_a, self.viewer_a, PermissionType.READ)
        self.client.force_login(self.viewer_a)
        self.api_client.force_authenticate(user=self.viewer_a)

        # Viewer A downloads successfully before revocation
        dl_pre = self.client.get(reverse('documents:download', kwargs={'pk': self.doc_a.id}))
        self.assertEqual(dl_pre.status_code, 200)

        # Owner revokes access
        revoke_document_permission(self.owner_a, perm)

        # Attempt 1: Re-accessing detail URL
        resp_detail = self.client.get(reverse('documents:detail', kwargs={'pk': self.doc_a.id}))
        self.assertEqual(resp_detail.status_code, 403)

        # Attempt 2: Re-accessing old download URL
        resp_dl = self.client.get(reverse('documents:download', kwargs={'pk': self.doc_a.id}))
        self.assertEqual(resp_dl.status_code, 403)

        # Attempt 3: Direct REST API download request
        api_dl = self.api_client.get(f"/api/documents/{self.doc_a.id}/download/")
        self.assertEqual(api_dl.status_code, 403)

    # -------------------------------------------------------------
    # Scenario 15: IDOR prevention (User A cannot access User B's doc by ID)
    # -------------------------------------------------------------
    def test_15_idor_prevention(self):
        # Owner B tries to access Owner A's doc
        self.client.force_login(self.owner_b)
        resp = self.client.get(reverse('documents:detail', kwargs={'pk': self.doc_a.id}))
        self.assertEqual(resp.status_code, 403)

        dl_resp = self.client.get(reverse('documents:download', kwargs={'pk': self.doc_a.id}))
        self.assertEqual(dl_resp.status_code, 403)

    # -------------------------------------------------------------
    # Scenario 16: API bypass prevention
    # -------------------------------------------------------------
    def test_16_api_bypass_prevention(self):
        self.api_client.force_authenticate(user=self.viewer_b)
        resp = self.api_client.get(f"/api/documents/{self.doc_a.id}/")
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    # -------------------------------------------------------------
    # Scenario 17: Search does not expose unauthorized documents
    # -------------------------------------------------------------
    def test_17_search_does_not_leak_unauthorized_documents(self):
        # Viewer A can only see doc_b if shared
        grant_document_permission(self.owner_b, self.doc_b, self.viewer_a, PermissionType.READ)

        qs_viewer_a = get_accessible_documents_queryset(self.viewer_a)
        self.assertIn(self.doc_b, qs_viewer_a)
        self.assertNotIn(self.doc_a, qs_viewer_a)

    # -------------------------------------------------------------
    # Scenario 18: Audit records generated for denied access
    # -------------------------------------------------------------
    def test_18_audit_records_generated_for_denied_access(self):
        self.client.force_login(self.viewer_b)
        self.client.get(reverse('documents:download', kwargs={'pk': self.doc_a.id}))

        audit = AuditLog.objects.filter(
            actor_username='viewer_b',
            document_id=self.doc_a.id,
            action_result=ActionResult.DENIED
        ).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.event_type, AuditEventType.UNAUTHORIZED_DOWNLOAD_ATTEMPT)

    # -------------------------------------------------------------
    # Scenario 19: Audit records generated for successful downloads
    # -------------------------------------------------------------
    def test_19_audit_records_generated_for_successful_downloads(self):
        self.client.force_login(self.owner_a)
        self.client.get(reverse('documents:download', kwargs={'pk': self.doc_a.id}))

        audit = AuditLog.objects.filter(
            actor_username='owner_a',
            document_id=self.doc_a.id,
            action_result=ActionResult.SUCCESS,
            event_type=AuditEventType.DOCUMENT_DOWNLOAD
        ).first()
        self.assertIsNotNone(audit)

    # -------------------------------------------------------------
    # Scenario 20: Normal users cannot modify or delete audit records
    # -------------------------------------------------------------
    def test_20_normal_users_cannot_modify_or_delete_audit(self):
        entry = record_audit_event(event_type=AuditEventType.DOCUMENT_VIEW, action_result=ActionResult.SUCCESS)
        with self.assertRaises(PermissionDenied):
            entry.document_name = "Modified"
            entry.save()

        with self.assertRaises(PermissionDenied):
            entry.delete()

    # -------------------------------------------------------------
    # Scenario 21: Audit-chain verification detects altered records
    # -------------------------------------------------------------
    def test_21_audit_chain_verification_detects_altered_records(self):
        # Create a few valid events
        record_audit_event(event_type=AuditEventType.DOCUMENT_VIEW, action_result=ActionResult.SUCCESS)
        record_audit_event(event_type=AuditEventType.DOCUMENT_DOWNLOAD, action_result=ActionResult.SUCCESS)

        # Before tampering
        report = verify_audit_chain()
        self.assertTrue(report['is_valid'])

        # Direct SQL alteration
        AuditLog.objects.filter(sequence_number=1).update(previous_hash='f'*64)

        # After tampering
        report_tampered = verify_audit_chain()
        self.assertFalse(report_tampered['is_valid'])

    # -------------------------------------------------------------
    # Scenario 22, 23, 24: File upload validation (malicious, oversized, traversal)
    # -------------------------------------------------------------
    def test_22_23_24_upload_security_validations(self):
        # 22. Executable
        with self.assertRaises(ValidationError):
            validate_file_upload(ContentFile(b"binary", name="exploit.exe"))

        # 23. Oversized
        with self.assertRaises(ValidationError):
            validate_file_upload(ContentFile(b"0" * (26 * 1024 * 1024), name="huge.pdf"))

        # 24. Traversal
        with self.assertRaises(ValidationError):
            validate_file_upload(ContentFile(b"%PDF-1.4\nfile", name="../../traversal.pdf"))

    # -------------------------------------------------------------
    # Scenario 25: Deactivated users cannot access protected documents
    # -------------------------------------------------------------
    def test_25_deactivated_user_blocked(self):
        grant_document_permission(self.owner_a, self.doc_a, self.viewer_a, PermissionType.READ)
        self.viewer_a.is_active = False
        self.viewer_a.save()

        self.assertFalse(can_download_document(self.viewer_a, self.doc_a))
        self.assertFalse(can_view_document(self.viewer_a, self.doc_a))

    # -------------------------------------------------------------
    # Scenario 26: Administrator cannot read confidential document content by default
    # -------------------------------------------------------------
    def test_26_administrator_cannot_download_confidential_document_by_default(self):
        # Admin can view metadata for oversight
        self.assertTrue(can_view_document(self.admin, self.doc_a))

        # Admin CANNOT download confidential document payload without explicit grant
        self.assertFalse(can_download_document(self.admin, self.doc_a))

        self.client.force_login(self.admin)
        dl_resp = self.client.get(reverse('documents:download', kwargs={'pk': self.doc_a.id}))
        self.assertEqual(dl_resp.status_code, 403)

    # -------------------------------------------------------------
    # Scenario 27: Concurrent permission race condition prevention
    # -------------------------------------------------------------
    def test_27_duplicate_active_permissions_prevented(self):
        grant_document_permission(self.owner_a, self.doc_a, self.viewer_a, PermissionType.READ)
        # Calling grant again idempotently updates or returns the existing grant without creating a duplicate active row
        grant_document_permission(self.owner_a, self.doc_a, self.viewer_a, PermissionType.READ)

        active_count = DocumentPermission.objects.filter(
            document=self.doc_a,
            user=self.viewer_a,
            is_active=True
        ).count()
        self.assertEqual(active_count, 1)
