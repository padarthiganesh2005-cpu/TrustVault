from rest_framework import permissions
from .services import can_view_document, can_edit_document, can_delete_document, can_manage_permissions

class CanViewDocumentPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return can_view_document(request.user, obj)

class CanEditDocumentPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return can_edit_document(request.user, obj)

class CanDeleteDocumentPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return can_delete_document(request.user, obj)

class CanManageDocumentPermissions(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return can_manage_permissions(request.user, obj)
