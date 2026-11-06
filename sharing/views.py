from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_POST
from django.core.exceptions import PermissionDenied, ValidationError
from rest_framework import views, status, permissions
from rest_framework.response import Response

from .models import DocumentPermission, PermissionHistory, PermissionType
from .forms import GrantPermissionForm
from .serializers import (
    DocumentPermissionSerializer,
    GrantPermissionSerializer,
    UpdatePermissionSerializer,
    PermissionHistorySerializer
)
from .services import (
    grant_document_permission,
    update_permission_level,
    revoke_document_permission
)
from documents.models import Document
from documents.services import can_manage_permissions
from accounts.models import CustomUser

# =====================================================================
# Django Template Views
# =====================================================================

@login_required
@require_POST
def grant_permission_view(request, doc_id):
    """Web action: Document owner grants READ or EDIT permission to another user."""
    document = get_object_or_404(Document, pk=doc_id)
    form = GrantPermissionForm(request.POST, document=document)
    if form.is_valid():
        target_user = form.cleaned_data['user']
        perm_type = form.cleaned_data['permission_type']
        try:
            grant_document_permission(
                granter=request.user,
                document=document,
                target_user=target_user,
                permission_type=perm_type
            )
            messages.success(
                request,
                f"Granted {perm_type} access to '{target_user.username}' for document '{document.name}'."
            )
        except (PermissionDenied, ValidationError) as e:
            messages.error(request, str(e))
    else:
        messages.error(request, "Failed to grant access. Please check form inputs.")

    return redirect('documents:detail', pk=document.id)

@login_required
@require_POST
def update_permission_view(request, pk):
    """Web action: Document owner toggles permission level (READ <-> EDIT)."""
    permission = get_object_or_404(DocumentPermission, pk=pk)
    new_type = request.POST.get('permission_type')
    try:
        update_permission_level(request.user, permission, new_type)
        messages.success(
            request,
            f"Updated permission for '{permission.user.username}' to {new_type}."
        )
    except (PermissionDenied, ValidationError) as e:
        messages.error(request, str(e))

    return redirect('documents:detail', pk=permission.document_id)

@login_required
@require_POST
def revoke_permission_view(request, pk):
    """
    Web action: Document owner revokes access.
    Revocation is immediate on the server side.
    """
    permission = get_object_or_404(DocumentPermission, pk=pk)
    doc_id = permission.document_id
    target_username = permission.user.username
    try:
        revoke_document_permission(request.user, permission)
        messages.warning(
            request,
            f"Access immediately revoked for '{target_username}'. Server will deny all subsequent access attempts."
        )
    except (PermissionDenied, ValidationError) as e:
        messages.error(request, str(e))

    return redirect('documents:detail', pk=doc_id)


# =====================================================================
# REST API Endpoints
# =====================================================================

class APIDocumentPermissionListCreateView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        document = get_object_or_404(Document, pk=pk)
        if not can_manage_permissions(request.user, document) and not request.user.is_admin_role:
            return Response(
                {"error": "Only the document owner or system administrator can inspect permission rosters."},
                status=status.HTTP_403_FORBIDDEN
            )
        perms = document.permissions.select_related('user', 'granted_by').all()
        serializer = DocumentPermissionSerializer(perms, many=True)
        return Response(serializer.data)

    def post(self, request, pk):
        document = get_object_or_404(Document, pk=pk)
        if not can_manage_permissions(request.user, document):
            return Response(
                {"error": "Only the document owner can grant permissions."},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = GrantPermissionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user_id = serializer.validated_data['user_id']
        perm_type = serializer.validated_data['permission_type']

        try:
            target_user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            return Response({"error": "Target user not found."}, status=status.HTTP_404_NOT_FOUND)

        try:
            perm = grant_document_permission(
                granter=request.user,
                document=document,
                target_user=target_user,
                permission_type=perm_type
            )
            return Response(DocumentPermissionSerializer(perm).data, status=status.HTTP_201_CREATED)
        except (PermissionDenied, ValidationError) as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class APIPermissionDetailView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, pk):
        permission = get_object_or_404(DocumentPermission, pk=pk)
        if not can_manage_permissions(request.user, permission.document):
            return Response(
                {"error": "Only the document owner can modify permissions."},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = UpdatePermissionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        new_type = serializer.validated_data['permission_type']
        try:
            perm = update_permission_level(request.user, permission, new_type)
            return Response(DocumentPermissionSerializer(perm).data)
        except (PermissionDenied, ValidationError) as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        permission = get_object_or_404(DocumentPermission, pk=pk)
        if not can_manage_permissions(request.user, permission.document):
            return Response(
                {"error": "Only the document owner can revoke permissions."},
                status=status.HTTP_403_FORBIDDEN
            )

        revoke_document_permission(request.user, permission)
        return Response(
            {"message": "Permission successfully revoked with immediate effect."},
            status=status.HTTP_200_OK
        )
