from django.test import TestCase
from django.core.files.base import ContentFile
from django.core.exceptions import ValidationError, PermissionDenied
from accounts.models import CustomUser, UserRole
from documents.models import Document, DocumentCategory
from documents.services import upload_document, soft_delete_document, restore_document
from documents.validators import validate_file_upload, sanitize_filename

class SecureFileUploadAndValidationTests(TestCase):
    def setUp(self):
        self.owner = CustomUser.objects.create_user(
            username='doc_owner',
            email='owner@vault.local',
            password='Password123!@#',
            role=UserRole.OWNER
        )
        self.other_user = CustomUser.objects.create_user(
            username='other_user',
            email='other@vault.local',
            password='Password123!@#',
            role=UserRole.VIEWER
        )

    def test_empty_file_rejected(self):
        f = ContentFile(b"", name="empty.pdf")
        with self.assertRaises(ValidationError) as ctx:
            validate_file_upload(f)
        self.assertIn("empty", str(ctx.exception).lower())

    def test_oversized_file_rejected(self):
        # 26 MB exceeds 25 MB limit
        oversized_data = b"0" * (26 * 1024 * 1024)
        f = ContentFile(oversized_data, name="large.pdf")
        with self.assertRaises(ValidationError) as ctx:
            validate_file_upload(f)
        self.assertIn("exceeds maximum permitted limit", str(ctx.exception))

    def test_executable_extension_rejected(self):
        f = ContentFile(b"binary payload", name="malware.exe")
        with self.assertRaises(ValidationError) as ctx:
            validate_file_upload(f)
        self.assertIn("not permitted", str(ctx.exception))

    def test_double_extension_attack_rejected(self):
        f = ContentFile(b"%PDF-1.4\nfake", name="invoice.exe.pdf")
        with self.assertRaises(ValidationError) as ctx:
            validate_file_upload(f)
        self.assertIn("Suspicious double-extension", str(ctx.exception))

    def test_path_traversal_filename_sanitized(self):
        dirty = "../../etc/passwd.pdf"
        sanitized = sanitize_filename(dirty)
        self.assertNotIn("..", sanitized)
        self.assertNotIn("/", sanitized)
        self.assertNotIn("\\", sanitized)
        self.assertEqual(sanitized, "passwd.pdf")

    def test_magic_bytes_mismatch_rejected(self):
        # A file with .pdf extension that actually starts with Windows PE executable header MZ
        f = ContentFile(b"MZ\x90\x00\x03\x00\x00\x00executable", name="trojan.pdf")
        with self.assertRaises(ValidationError) as ctx:
            validate_file_upload(f)
        self.assertIn("Binary executable signature detected", str(ctx.exception))

    def test_soft_delete_and_restore(self):
        valid_pdf = ContentFile(b"%PDF-1.4\ncontent", name="valid.pdf")
        doc = upload_document(self.owner, valid_pdf, name="Retained Doc")
        self.assertFalse(doc.is_deleted)

        # Other user cannot delete
        with self.assertRaises(PermissionDenied):
            soft_delete_document(self.other_user, doc)

        # Owner can delete
        soft_delete_document(self.owner, doc)
        doc.refresh_from_db()
        self.assertTrue(doc.is_deleted)

        # Other user cannot restore
        with self.assertRaises(PermissionDenied):
            restore_document(self.other_user, doc)

        # Owner restores
        restore_document(self.owner, doc)
        doc.refresh_from_db()
        self.assertFalse(doc.is_deleted)
