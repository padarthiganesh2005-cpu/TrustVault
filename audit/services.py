import hashlib
import json
import logging
from typing import Optional, Dict, Any, Tuple
from django.db import transaction
from django.utils import timezone
from .models import AuditLog, AuditEventType, ActionResult, SecurityEvent
from .middleware import get_current_request, get_client_ip

logger = logging.getLogger('audit')

GENESIS_HASH = "0" * 64

def canonicalize_event_payload(
    sequence_number: int,
    actor_username: str,
    event_type: str,
    document_id: Optional[str],
    target_username: str,
    action_result: str,
    ip_address: Optional[str],
    timestamp_iso: str,
    metadata: Dict[str, Any]
) -> str:
    """
    Produce a deterministic, canonical JSON string representing the event.
    Keys are strictly sorted with no extra whitespace to guarantee reproducible hashes.
    """
    payload = {
        "sequence_number": sequence_number,
        "actor": actor_username or "ANONYMOUS",
        "event_type": event_type,
        "document_id": str(document_id) if document_id else "",
        "target": target_username or "",
        "action_result": action_result,
        "ip_address": ip_address or "",
        "timestamp": timestamp_iso,
        "metadata": metadata or {}
    }
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), default=str)

def compute_record_hash(previous_hash: str, canonical_payload: str) -> str:
    """
    Calculate the SHA-256 hash chaining the previous record's hash with current event data:
      current_hash = SHA256(previous_hash + canonical_payload)
    """
    combined = f"{previous_hash}{canonical_payload}"
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()

def record_audit_event(
    event_type: str,
    action_result: str = ActionResult.SUCCESS,
    actor=None,
    document_id=None,
    document_name: str = "",
    target_user=None,
    target_username: str = "",
    ip_address: Optional[str] = None,
    user_agent: str = "",
    metadata: Optional[Dict[str, Any]] = None,
    request=None
) -> AuditLog:
    """
    Append an immutable, cryptographically chained audit record.
    Thread-safe and atomic with database lock.
    """
    if metadata is None:
        metadata = {}

    req = request or get_current_request()
    if req:
        if not ip_address:
            ip_address = get_client_ip(req)
        if not user_agent:
            user_agent = req.META.get('HTTP_USER_AGENT', '')
        if actor is None and hasattr(req, 'user') and req.user.is_authenticated:
            actor = req.user

    actor_username = actor.username if actor else "ANONYMOUS"
    actor_role = getattr(actor, 'role', '') if actor else ""

    if target_user and not target_username:
        target_username = target_user.username

    now = timezone.now()
    now_iso = now.isoformat()

    with transaction.atomic():
        # Retrieve the latest audit log entry using select_for_update to serialize insertions
        last_log = AuditLog.objects.select_for_update().order_by('-sequence_number').first()

        if last_log:
            next_seq = last_log.sequence_number + 1
            prev_hash = last_log.current_hash
        else:
            next_seq = 1
            prev_hash = GENESIS_HASH

        canonical_payload = canonicalize_event_payload(
            sequence_number=next_seq,
            actor_username=actor_username,
            event_type=event_type,
            document_id=str(document_id) if document_id else "",
            target_username=target_username,
            action_result=action_result,
            ip_address=ip_address,
            timestamp_iso=now_iso,
            metadata=metadata
        )

        curr_hash = compute_record_hash(prev_hash, canonical_payload)

        # Store canonical timestamp in metadata for verifiable deterministic reproduction
        metadata_with_ts = dict(metadata)
        metadata_with_ts['_canonical_ts'] = now_iso

        audit_entry = AuditLog(
            sequence_number=next_seq,
            actor=actor if actor and getattr(actor, 'is_authenticated', False) else None,
            actor_username=actor_username,
            actor_role=actor_role,
            event_type=event_type,
            document_id=document_id,
            document_name=document_name,
            target_user=target_user,
            target_username=target_username,
            action_result=action_result,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata_with_ts,
            timestamp=now,
            previous_hash=prev_hash,
            current_hash=curr_hash
        )
        audit_entry.save()

        # Security Alerting Trigger on Denied Actions
        if action_result == ActionResult.DENIED or 'UNAUTHORIZED' in event_type:
            _check_security_thresholds(actor_username, ip_address, event_type, document_id, metadata)

        return audit_entry

def _check_security_thresholds(actor_username: str, ip_address: Optional[str], event_type: str, document_id, metadata: dict):
    """
    Automated heuristic detection for suspicious patterns:
    - Multiple unauthorized attempts within short window
    - Brute force attempts
    """
    try:
        ten_minutes_ago = timezone.now() - timezone.timedelta(minutes=10)
        recent_denied_count = AuditLog.objects.filter(
            action_result=ActionResult.DENIED,
            timestamp__gte=ten_minutes_ago
        ).filter(
            models_q(actor_username=actor_username, ip_address=ip_address)
        ).count()

        if recent_denied_count >= 3:
            severity = 'HIGH' if recent_denied_count >= 5 else 'MEDIUM'
            desc = (
                f"Suspicious activity detected: {recent_denied_count} denied access attempts "
                f"by actor '{actor_username}' (IP: {ip_address}) in the last 10 minutes. "
                f"Latest event: {event_type} on document {document_id or 'N/A'}."
            )
            # Avoid duplicating active unresolved alert
            existing = SecurityEvent.objects.filter(
                actor_username=actor_username,
                is_resolved=False,
                created_at__gte=ten_minutes_ago
            ).first()

            if not existing:
                SecurityEvent.objects.create(
                    event_type="UNAUTHORIZED_ACCESS_BURST",
                    severity=severity,
                    actor_username=actor_username,
                    ip_address=ip_address,
                    description=desc,
                    details={
                        "recent_denied_count": recent_denied_count,
                        "latest_event_type": event_type,
                        "document_id": str(document_id) if document_id else None,
                        "metadata": metadata
                    }
                )
    except Exception as e:
        logger.error(f"Error checking security thresholds: {e}")

def models_q(actor_username: str, ip_address: Optional[str]):
    from django.db.models import Q
    if actor_username != 'ANONYMOUS':
        return Q(actor_username=actor_username)
    return Q(ip_address=ip_address)

def verify_audit_chain() -> Dict[str, Any]:
    """
    Verify the cryptographic integrity of the entire audit chain.
    Iterates sequentially through all records from sequence 1 to N.
    Verifies:
      1. Sequence continuity without gaps or out-of-order records.
      2. Previous hash linkage to previous record's current_hash.
      3. Cryptographic hash reproduction matching current_hash.
    """
    logs = AuditLog.objects.all().order_by('sequence_number')
    total_records = logs.count()

    if total_records == 0:
        return {
            "is_valid": True,
            "total_records": 0,
            "corrupted_at": None,
            "details": "Audit chain is empty. Genesis state intact."
        }

    expected_prev_hash = GENESIS_HASH
    expected_seq = 1

    for record in logs.iterator():
        # Check sequence continuity
        if record.sequence_number != expected_seq:
            return {
                "is_valid": False,
                "total_records": total_records,
                "corrupted_at": record.sequence_number,
                "details": f"Sequence discontinuity detected. Expected #{expected_seq}, found #{record.sequence_number}."
            }

        # Check previous_hash link
        if record.previous_hash != expected_prev_hash:
            return {
                "is_valid": False,
                "total_records": total_records,
                "corrupted_at": record.sequence_number,
                "details": (
                    f"Hash link broken at sequence #{record.sequence_number}. "
                    f"Recorded previous_hash '{record.previous_hash}' does not match expected '{expected_prev_hash}'."
                )
            }

        # Verify hash calculation
        canonical_ts = record.metadata.get('_canonical_ts', record.timestamp.isoformat())
        # Clean metadata copy without _canonical_ts for payload
        meta_clean = {k: v for k, v in record.metadata.items() if k != '_canonical_ts'}

        canonical_payload = canonicalize_event_payload(
            sequence_number=record.sequence_number,
            actor_username=record.actor_username,
            event_type=record.event_type,
            document_id=str(record.document_id) if record.document_id else "",
            target_username=record.target_username,
            action_result=record.action_result,
            ip_address=record.ip_address,
            timestamp_iso=canonical_ts,
            metadata=meta_clean
        )

        recalculated_hash = compute_record_hash(record.previous_hash, canonical_payload)
        if recalculated_hash != record.current_hash:
            return {
                "is_valid": False,
                "total_records": total_records,
                "corrupted_at": record.sequence_number,
                "details": (
                    f"Cryptographic tampering detected at sequence #{record.sequence_number}. "
                    f"Stored hash '{record.current_hash}' does not match recalculated '{recalculated_hash}'."
                )
            }

        expected_prev_hash = record.current_hash
        expected_seq += 1

    return {
        "is_valid": True,
        "total_records": total_records,
        "corrupted_at": None,
        "details": f"All {total_records} audit records successfully verified. Cryptographic hash chain is intact."
    }
