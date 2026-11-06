import io
import os
from django.core.management.base import BaseCommand
from django.core.files.base import ContentFile
from django.utils import timezone
from accounts.models import CustomUser, UserRole
from documents.models import DocumentCategory, Document
from documents.services import upload_document, serve_secure_file
from sharing.models import PermissionType
from sharing.services import grant_document_permission, revoke_document_permission
from audit.services import record_audit_event, verify_audit_chain
from audit.models import AuditEventType, ActionResult

class Command(BaseCommand):
    help = 'Seed database with realistic demo accounts, categories, documents, and audit history.'

    def handle(self, *args, **options):
        self.stdout.write(self.style.NOTICE("Initializing TrustVault Demo Seed Data..."))

        # 1. Create Core Users
        admin_user, _ = CustomUser.objects.get_or_create(
            username='admin',
            defaults={
                'email': 'admin@trustvault.local',
                'role': UserRole.ADMIN,
                'department': 'Information Security & Compliance',
                'is_staff': True,
                'is_superuser': True,
            }
        )
        admin_user.set_password('AdminPass123!@#')
        admin_user.save()

        owner_a, _ = CustomUser.objects.get_or_create(
            username='alice_owner',
            defaults={
                'email': 'alice.owner@trustvault.local',
                'role': UserRole.OWNER,
                'department': 'Finance & Executive Operations',
            }
        )
        owner_a.set_password('OwnerPass123!@#')
        owner_a.save()

        owner_b, _ = CustomUser.objects.get_or_create(
            username='bob_owner',
            defaults={
                'email': 'bob.owner@trustvault.local',
                'role': UserRole.OWNER,
                'department': 'Core Engineering & Infrastructure',
            }
        )
        owner_b.set_password('OwnerPass123!@#')
        owner_b.save()

        viewer_a, _ = CustomUser.objects.get_or_create(
            username='charlie_viewer',
            defaults={
                'email': 'charlie.viewer@trustvault.local',
                'role': UserRole.VIEWER,
                'department': 'External Advisory & Auditing',
            }
        )
        viewer_a.set_password('ViewerPass123!@#')
        viewer_a.save()

        viewer_b, _ = CustomUser.objects.get_or_create(
            username='david_viewer',
            defaults={
                'email': 'david.viewer@trustvault.local',
                'role': UserRole.VIEWER,
                'department': 'Vendor Management & Legal',
            }
        )
        viewer_b.set_password('ViewerPass123!@#')
        viewer_b.save()

        self.stdout.write(self.style.SUCCESS("[OK] Demo users created successfully."))

        # 2. Create Document Categories
        categories_data = [
            ("Financial Reports", "financial-reports", "Quarterly statements, audit logs, and capital forecasts."),
            ("Legal & Compliance", "legal-compliance", "NDAs, master service agreements, and regulatory filings."),
            ("Human Resources", "human-resources", "Staff policies, executive compensation, and organizational handbooks."),
            ("Engineering & Architecture", "engineering-architecture", "Zero-trust diagrams, security specs, and DR playbooks."),
            ("Executive Briefings", "executive-briefings", "Board meeting records, strategic acquisitions, and founder memos."),
        ]
        cat_map = {}
        for name, slug, desc in categories_data:
            cat, _ = DocumentCategory.objects.get_or_create(slug=slug, defaults={'name': name, 'description': desc})
            cat_map[slug] = cat

        self.stdout.write(self.style.SUCCESS("[OK] Document categories established."))

        # Sample valid document payloads
        pdf_content = b"%PDF-1.5\n%TrustVault Sample Confidential Document Payload\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
        docx_content = b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00!\x00TrustVault Word Document Sample Payload"
        xlsx_content = b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00!\x00TrustVault Excel Spreadsheet Sample Payload"
        txt_content = b"TrustVault Security Assessment and Architecture Specification\nClassification: RESTRICTED\nOwner: Security Engineering"

        # 3. Create Documents if not already present
        if not Document.objects.exists():
            docs_to_create = [
                # Alice's Documents
                {
                    'owner': owner_a,
                    'name': 'Q3 Financial Audit & Ledger',
                    'filename': 'Q3_Financial_Audit_2026.pdf',
                    'content': pdf_content,
                    'category': cat_map['financial-reports'],
                    'tags': 'finance, audit, q3, confidential',
                    'desc': 'Verified Q3 financial ledger detailing company expenditures and auditor notes.'
                },
                {
                    'owner': owner_a,
                    'name': 'Series B Term Sheet Confidential',
                    'filename': 'Series_B_Term_Sheet.pdf',
                    'content': pdf_content,
                    'category': cat_map['financial-reports'],
                    'tags': 'investment, funding, term-sheet',
                    'desc': 'Confidential term sheet outlining proposed venture capital funding terms.'
                },
                {
                    'owner': owner_a,
                    'name': 'Master Services Agreement Snovasys',
                    'filename': 'MSA_Snovasys_2026.docx',
                    'content': docx_content,
                    'category': cat_map['legal-compliance'],
                    'tags': 'contracts, legal, msa, snovasys',
                    'desc': 'Master services agreement contract and operational terms.'
                },
                {
                    'owner': owner_a,
                    'name': 'Employee Handbook 2026',
                    'filename': 'Employee_Handbook_2026.docx',
                    'content': docx_content,
                    'category': cat_map['human-resources'],
                    'tags': 'hr, policy, handbook',
                    'desc': 'Internal company policy handbook and code of professional conduct.'
                },
                {
                    'owner': owner_a,
                    'name': 'Zero Trust Architecture Specification',
                    'filename': 'Zero_Trust_Architecture.pdf',
                    'content': pdf_content,
                    'category': cat_map['engineering-architecture'],
                    'tags': 'security, architecture, zero-trust',
                    'desc': 'Complete architectural blueprint for zero-trust document access control.'
                },
                # Bob's Documents
                {
                    'owner': owner_b,
                    'name': 'Database Disaster Recovery Plan',
                    'filename': 'Database_DR_Plan.docx',
                    'content': docx_content,
                    'category': cat_map['engineering-architecture'],
                    'tags': 'database, dr, infrastructure',
                    'desc': 'Step-by-step failover and recovery procedures for primary vault database storage.'
                },
                {
                    'owner': owner_b,
                    'name': 'Executive Board Minutes Oct 2026',
                    'filename': 'Executive_Board_Minutes.pdf',
                    'content': pdf_content,
                    'category': cat_map['executive-briefings'],
                    'tags': 'board, executive, restricted',
                    'desc': 'Strictly confidential minutes of the Q4 Board of Directors assembly.'
                },
                {
                    'owner': owner_b,
                    'name': 'Customer Security Assessment 2026',
                    'filename': 'Customer_Security_Assessment.xlsx',
                    'content': xlsx_content,
                    'category': cat_map['legal-compliance'],
                    'tags': 'soc2, compliance, security-assessment',
                    'desc': 'Enterprise vendor security evaluation and SOC2 readiness scorecards.'
                },
                {
                    'owner': owner_b,
                    'name': 'Executive Compensation Review',
                    'filename': 'Executive_Compensation_Review.xlsx',
                    'content': xlsx_content,
                    'category': cat_map['human-resources'],
                    'tags': 'compensation, executive, hr',
                    'desc': 'Restricted benchmark analysis on executive compensation and bonus pools.'
                },
                {
                    'owner': owner_b,
                    'name': 'Cloud Infrastructure Budget 2027',
                    'filename': 'Cloud_Infrastructure_Budget.xlsx',
                    'content': xlsx_content,
                    'category': cat_map['financial-reports'],
                    'tags': 'cloud, budget, aws, gcp',
                    'desc': 'Projected 2027 compute, storage, and egress cost allocation model.'
                },
                {
                    'owner': owner_a,
                    'name': 'Incident Response Playbook v2',
                    'filename': 'Incident_Response_Playbook.txt',
                    'content': txt_content,
                    'category': cat_map['engineering-architecture'],
                    'tags': 'security, incident-response, playbook',
                    'desc': 'Standard operating procedures for rapid containment of security breaches.'
                },
            ]

            created_docs = {}
            for item in docs_to_create:
                file_obj = ContentFile(item['content'], name=item['filename'])
                doc = upload_document(
                    user=item['owner'],
                    file_obj=file_obj,
                    name=item['name'],
                    description=item['desc'],
                    category=item['category'],
                    tags=item['tags']
                )
                created_docs[item['name']] = doc

            self.stdout.write(self.style.SUCCESS(f"[OK] Created {len(created_docs)} sample documents in private storage."))

            # 4. Create Realistic Permission Combinations & Transitions
            doc_q3 = created_docs['Q3 Financial Audit & Ledger']
            doc_zt = created_docs['Zero Trust Architecture Specification']
            doc_msa = created_docs['Master Services Agreement Snovasys']
            doc_dr = created_docs['Database Disaster Recovery Plan']

            # Charlie gets READ on Q3 Audit
            grant_document_permission(owner_a, doc_q3, viewer_a, PermissionType.READ)

            # Charlie gets EDIT on Zero Trust Spec
            grant_document_permission(owner_a, doc_zt, viewer_a, PermissionType.EDIT)

            # Charlie gets READ on Database DR Plan
            grant_document_permission(owner_b, doc_dr, viewer_a, PermissionType.READ)

            # David was granted READ on MSA, and then Alice revoked it!
            perm_msa = grant_document_permission(owner_a, doc_msa, viewer_b, PermissionType.READ)
            revoke_document_permission(owner_a, perm_msa)

            self.stdout.write(self.style.SUCCESS("[OK] Permission grants and revocation transition created."))

            # 5. Record Sample Access & Denied Attempts in Audit Trail
            # Charlie successfully downloads Q3 Audit
            record_audit_event(
                event_type=AuditEventType.DOCUMENT_DOWNLOAD,
                action_result=ActionResult.SUCCESS,
                actor=viewer_a,
                document_id=doc_q3.id,
                document_name=doc_q3.name,
                ip_address='192.168.1.105',
                metadata={'status': 'authorized_download', 'version': 1}
            )

            # David attempts to download MSA (after revocation) -> DENIED
            record_audit_event(
                event_type=AuditEventType.UNAUTHORIZED_DOWNLOAD_ATTEMPT,
                action_result=ActionResult.DENIED,
                actor=viewer_b,
                document_id=doc_msa.id,
                document_name=doc_msa.name,
                ip_address='192.168.1.142',
                metadata={'reason': 'Access revoked by owner.', 'attempted_url': f'/api/documents/{doc_msa.id}/download/'}
            )

            # David attempts IDOR access to Board Minutes (unshared) -> DENIED
            doc_board = created_docs['Executive Board Minutes Oct 2026']
            record_audit_event(
                event_type=AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT,
                action_result=ActionResult.DENIED,
                actor=viewer_b,
                document_id=doc_board.id,
                document_name=doc_board.name,
                ip_address='192.168.1.142',
                metadata={'reason': 'IDOR probing attempt: User has no grant on this document.'}
            )

            self.stdout.write(self.style.SUCCESS("[OK] Simulated security events and audit log entries generated."))

        # 6. Verify Audit Hash Chain
        verification = verify_audit_chain()
        self.stdout.write(self.style.SUCCESS(
            f"[OK] Audit Hash Chain Verification: {verification['details']}"
        ))

        self.stdout.write(self.style.NOTICE("""
=============================================================================
TrustVault Ready for Demonstration!
-----------------------------------------------------------------------------
Evaluation Credentials:
  - Administrator:  username: admin           password: AdminPass123!@#
  - Document Owner: username: alice_owner     password: OwnerPass123!@#
  - Document Owner: username: bob_owner       password: OwnerPass123!@#
  - Viewer A:       username: charlie_viewer  password: ViewerPass123!@#
  - Viewer B:       username: david_viewer    password: ViewerPass123!@#
=============================================================================
        """))
