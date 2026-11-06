from rest_framework import permissions
from documents.services import can_manage_permissions

class CanManageSharingPermission(permissions.BasePermission):
    """Only the document owner can grant, modify, or revoke permissions."""
    def has_object_permission(self, request, view, obj):
        # obj can be a DocumentPermission or Document
        doc = getattr(obj, 'document', obj)
        return can_manage_permissions(request.user, doc)
