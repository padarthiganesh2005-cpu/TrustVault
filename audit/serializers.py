from rest_framework import serializers
from .models import AuditLog, SecurityEvent

class AuditLogSerializer(serializers.ModelSerializer):
    event_type_display = serializers.CharField(source='get_event_type_display', read_only=True)

    class Meta:
        model = AuditLog
        fields = (
            'id', 'sequence_number', 'actor', 'actor_username', 'actor_role',
            'event_type', 'event_type_display', 'document_id', 'document_name',
            'target_user', 'target_username', 'action_result', 'ip_address',
            'user_agent', 'metadata', 'timestamp', 'previous_hash', 'current_hash'
        )
        read_only_fields = fields

class SecurityEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityEvent
        fields = (
            'id', 'event_type', 'severity', 'actor_username',
            'ip_address', 'description', 'details', 'is_resolved',
            'created_at', 'resolved_at'
        )
        read_only_fields = ('id', 'created_at')
