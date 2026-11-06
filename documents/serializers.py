from rest_framework import serializers
from .models import Document, DocumentCategory, DocumentVersion
from accounts.serializers import UserSerializer
from .validators import validate_file_upload

class DocumentCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = DocumentCategory
        fields = ('id', 'name', 'slug', 'description', 'created_at')

class DocumentVersionSerializer(serializers.ModelSerializer):
    uploaded_by_username = serializers.CharField(source='uploaded_by.username', read_only=True)
    formatted_size = serializers.CharField(read_only=True)

    class Meta:
        model = DocumentVersion
        fields = (
            'id', 'version_number', 'original_filename', 'file_size',
            'formatted_size', 'file_hash', 'uploaded_by_username',
            'change_summary', 'created_at'
        )

class DocumentDetailSerializer(serializers.ModelSerializer):
    owner_username = serializers.CharField(source='owner.username', read_only=True)
    category_name = serializers.CharField(source='category.name', read_only=True)
    formatted_size = serializers.CharField(read_only=True)
    tag_list = serializers.ListField(read_only=True)
    versions = DocumentVersionSerializer(many=True, read_only=True)
    download_url = serializers.SerializerMethodField()

    class Meta:
        model = Document
        fields = (
            'id', 'name', 'description', 'category', 'category_name',
            'tags', 'tag_list', 'file_type', 'file_extension',
            'file_size', 'formatted_size', 'file_hash',
            'owner', 'owner_username', 'version', 'is_deleted',
            'created_at', 'updated_at', 'versions', 'download_url'
        )
        read_only_fields = (
            'id', 'file_type', 'file_extension', 'file_size',
            'file_hash', 'owner', 'version', 'is_deleted',
            'created_at', 'updated_at'
        )

    def get_download_url(self, obj) -> str:
        return f"/api/documents/{obj.id}/download/"

class DocumentUploadSerializer(serializers.ModelSerializer):
    file = serializers.FileField(required=True)

    class Meta:
        model = Document
        fields = ('id', 'name', 'description', 'category', 'tags', 'file')

    def validate_file(self, value):
        validate_file_upload(value)
        return value
