from rest_framework import serializers
from .models import DocumentPermission, PermissionHistory, PermissionType

class DocumentPermissionSerializer(serializers.ModelSerializer):
    user_username = serializers.CharField(source='user.username', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    granted_by_username = serializers.CharField(source='granted_by.username', read_only=True)
    revoked_by_username = serializers.CharField(source='revoked_by.username', read_only=True)
    permission_type_display = serializers.CharField(source='get_permission_type_display', read_only=True)

    class Meta:
        model = DocumentPermission
        fields = (
            'id', 'document', 'user', 'user_username', 'user_email',
            'permission_type', 'permission_type_display', 'granted_by',
            'granted_by_username', 'is_active', 'granted_at',
            'updated_at', 'revoked_at', 'revoked_by_username'
        )
        read_only_fields = (
            'id', 'granted_by', 'is_active', 'granted_at',
            'updated_at', 'revoked_at', 'revoked_by'
        )

class GrantPermissionSerializer(serializers.Serializer):
    user_id = serializers.IntegerField(required=True)
    permission_type = serializers.ChoiceField(choices=PermissionType.choices, default=PermissionType.READ)

class UpdatePermissionSerializer(serializers.Serializer):
    permission_type = serializers.ChoiceField(choices=PermissionType.choices, required=True)

class PermissionHistorySerializer(serializers.ModelSerializer):
    target_username = serializers.CharField(source='target_user.username', read_only=True)
    performed_by_username = serializers.CharField(source='performed_by.username', read_only=True)

    class Meta:
        model = PermissionHistory
        fields = (
            'id', 'document', 'target_user', 'target_username',
            'action', 'previous_type', 'new_type', 'performed_by',
            'performed_by_username', 'timestamp', 'notes'
        )
