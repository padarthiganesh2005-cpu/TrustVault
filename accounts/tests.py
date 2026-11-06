from django.test import TestCase, Client
from django.urls import reverse
from accounts.models import CustomUser, UserRole
from audit.models import AuditLog, AuditEventType, ActionResult

class AccountAuthenticationSecurityTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            username='test_user',
            email='test@vault.local',
            password='Password123!@#',
            role=UserRole.VIEWER
        )

    def test_successful_login_logs_audit(self):
        response = self.client.post(reverse('login'), {
            'username': 'test_user',
            'password': 'Password123!@#'
        })
        self.assertEqual(response.status_code, 302)
        audit = AuditLog.objects.filter(actor_username='test_user', event_type=AuditEventType.USER_LOGIN).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.action_result, ActionResult.SUCCESS)

    def test_failed_login_logs_audit_denied(self):
        response = self.client.post(reverse('login'), {
            'username': 'test_user',
            'password': 'WrongPassword123'
        })
        self.assertEqual(response.status_code, 200)
        audit = AuditLog.objects.filter(event_type=AuditEventType.USER_LOGIN_FAILED).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.action_result, ActionResult.DENIED)

    def test_deactivated_user_cannot_login(self):
        self.user.is_active = False
        self.user.save()
        response = self.client.post(reverse('login'), {
            'username': 'test_user',
            'password': 'Password123!@#'
        })
        self.assertEqual(response.status_code, 200)
        # Verify not authenticated
        self.assertNotIn('_auth_user_id', self.client.session)
        audit = AuditLog.objects.filter(event_type=AuditEventType.USER_LOGIN_FAILED, target_username='test_user').first()
        self.assertIsNotNone(audit)
