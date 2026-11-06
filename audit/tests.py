from django.test import TestCase
from django.core.exceptions import PermissionDenied
from audit.models import AuditLog, AuditEventType, ActionResult
from audit.services import record_audit_event, verify_audit_chain, GENESIS_HASH

class CryptographicAuditChainTests(TestCase):
    def test_audit_records_are_append_only_and_immutable(self):
        entry = record_audit_event(
            event_type=AuditEventType.DOCUMENT_VIEW,
            action_result=ActionResult.SUCCESS,
            document_name="Test Doc"
        )
        # Attempt direct update
        entry.document_name = "Tampered Doc"
        with self.assertRaises(PermissionDenied):
            entry.save()

        # Attempt direct deletion
        with self.assertRaises(PermissionDenied):
            entry.delete()

    def test_hash_chain_continuity_and_verification(self):
        entry1 = record_audit_event(
            event_type=AuditEventType.USER_LOGIN,
            action_result=ActionResult.SUCCESS
        )
        entry2 = record_audit_event(
            event_type=AuditEventType.DOCUMENT_UPLOAD,
            action_result=ActionResult.SUCCESS,
            document_name="Confidential Plan"
        )
        entry3 = record_audit_event(
            event_type=AuditEventType.DOCUMENT_DOWNLOAD,
            action_result=ActionResult.SUCCESS,
            document_name="Confidential Plan"
        )

        self.assertEqual(entry1.previous_hash, GENESIS_HASH)
        self.assertEqual(entry2.previous_hash, entry1.current_hash)
        self.assertEqual(entry3.previous_hash, entry2.current_hash)

        # Run verification service
        report = verify_audit_chain()
        self.assertTrue(report['is_valid'])
        self.assertEqual(report['total_records'], 3)
        self.assertIsNone(report['corrupted_at'])

    def test_hash_chain_detects_tampering(self):
        record_audit_event(event_type=AuditEventType.USER_LOGIN, action_result=ActionResult.SUCCESS)
        record_audit_event(event_type=AuditEventType.DOCUMENT_VIEW, action_result=ActionResult.SUCCESS)
        record_audit_event(event_type=AuditEventType.DOCUMENT_DOWNLOAD, action_result=ActionResult.SUCCESS)

        # Bypass normal model save via direct SQL update to simulate malicious database tampering
        target = AuditLog.objects.get(sequence_number=2)
        AuditLog.objects.filter(pk=target.pk).update(current_hash='a' * 64)

        report = verify_audit_chain()
        self.assertFalse(report['is_valid'])
        self.assertEqual(report['corrupted_at'], 2)
        self.assertIn("Cryptographic tampering detected", report['details'])
