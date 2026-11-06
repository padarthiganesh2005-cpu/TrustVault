from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_POST
from django.core.exceptions import PermissionDenied
from django.utils.translation import gettext_lazy as _
from rest_framework import views, generics, status, permissions
from rest_framework.response import Response

from .models import CustomUser, UserRole
from .forms import CustomLoginForm, UserRegisterForm, UserProfileForm, AdminUserManagementForm
from .serializers import UserSerializer, UserRegisterSerializer, LoginSerializer
from audit.services import record_audit_event
from audit.models import AuditEventType, ActionResult

# =====================================================================
# Django Template Views
# =====================================================================

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:index')

    if request.method == 'POST':
        form = CustomLoginForm(request, data=request.POST)
        username_attempt = request.POST.get('username', '')
        if form.is_valid():
            user = form.get_user()
            if not user.is_active:
                record_audit_event(
                    event_type=AuditEventType.USER_LOGIN_FAILED,
                    action_result=ActionResult.DENIED,
                    actor=None,
                    target_user=user,
                    target_username=user.username,
                    metadata={"reason": "Account is deactivated."},
                    request=request
                )
                messages.error(request, "This account has been deactivated. Please contact an administrator.")
                return render(request, 'accounts/login.html', {'form': form})

            login(request, user)
            record_audit_event(
                event_type=AuditEventType.USER_LOGIN,
                action_result=ActionResult.SUCCESS,
                actor=user,
                metadata={"role": user.role},
                request=request
            )
            messages.success(request, f"Welcome back, {user.username}!")
            next_url = request.GET.get('next')
            return redirect(next_url if next_url else 'dashboard:index')
        else:
            record_audit_event(
                event_type=AuditEventType.USER_LOGIN_FAILED,
                action_result=ActionResult.DENIED,
                actor=None,
                target_username=username_attempt,
                metadata={"reason": "Invalid credentials."},
                request=request
            )
            messages.error(request, "Invalid username or password.")
    else:
        form = CustomLoginForm()

    return render(request, 'accounts/login.html', {'form': form})

@login_required
def logout_view(request):
    user = request.user
    record_audit_event(
        event_type=AuditEventType.USER_LOGOUT,
        action_result=ActionResult.SUCCESS,
        actor=user,
        request=request
    )
    logout(request)
    messages.info(request, "You have been securely logged out.")
    return redirect('login')

def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:index')

    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            record_audit_event(
                event_type=AuditEventType.USER_REGISTERED,
                action_result=ActionResult.SUCCESS,
                actor=user,
                metadata={"role": user.role, "department": user.department},
                request=request
            )
            login(request, user)
            messages.success(request, f"Account created successfully as {user.get_role_display()}!")
            return redirect('dashboard:index')
    else:
        form = UserRegisterForm()

    return render(request, 'accounts/register.html', {'form': form})

@login_required
def profile_view(request):
    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Your profile details have been updated.")
            return redirect('accounts:profile')
    else:
        form = UserProfileForm(instance=request.user)

    return render(request, 'accounts/profile.html', {'form': form})

@login_required
def user_management_view(request):
    """Administrator-only user oversight view."""
    if not request.user.is_admin_role:
        raise PermissionDenied("Only administrators can access user management.")

    users = CustomUser.objects.all().order_by('-date_joined')
    return render(request, 'accounts/user_management.html', {'managed_users': users})

@login_required
@require_POST
def toggle_user_status_view(request, user_id):
    """Admin activation / deactivation of user accounts."""
    if not request.user.is_admin_role:
        raise PermissionDenied("Only administrators can modify user status.")

    target_user = get_object_or_404(CustomUser, pk=user_id)
    if target_user.id == request.user.id:
        messages.error(request, "You cannot deactivate your own administrative account.")
        return redirect('accounts:user_management')

    target_user.is_active = not target_user.is_active
    target_user.save()

    event = AuditEventType.USER_ACTIVATED if target_user.is_active else AuditEventType.USER_DEACTIVATED
    record_audit_event(
        event_type=event,
        action_result=ActionResult.SUCCESS,
        actor=request.user,
        target_user=target_user,
        target_username=target_user.username,
        metadata={"new_status": "ACTIVE" if target_user.is_active else "DEACTIVATED"},
        request=request
    )

    action_name = "activated" if target_user.is_active else "deactivated"
    messages.success(request, f"User '{target_user.username}' has been {action_name}.")
    return redirect('accounts:user_management')


# =====================================================================
# REST API Endpoints
# =====================================================================

class APILoginView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        user = authenticate(request, username=username, password=password)

        if user:
            if not user.is_active:
                record_audit_event(
                    event_type=AuditEventType.USER_LOGIN_FAILED,
                    action_result=ActionResult.DENIED,
                    actor=None,
                    target_user=user,
                    target_username=user.username,
                    metadata={"reason": "Account is deactivated (API)."},
                    request=request
                )
                return Response(
                    {"error": "Account is deactivated."},
                    status=status.HTTP_403_FORBIDDEN
                )

            login(request, user)
            record_audit_event(
                event_type=AuditEventType.USER_LOGIN,
                action_result=ActionResult.SUCCESS,
                actor=user,
                metadata={"role": user.role, "channel": "API"},
                request=request
            )
            return Response(UserSerializer(user).data)
        else:
            record_audit_event(
                event_type=AuditEventType.USER_LOGIN_FAILED,
                action_result=ActionResult.DENIED,
                actor=None,
                target_username=username,
                metadata={"reason": "Invalid credentials (API)."},
                request=request
            )
            return Response(
                {"error": "Invalid credentials."},
                status=status.HTTP_401_UNAUTHORIZED
            )

class APILogoutView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        record_audit_event(
            event_type=AuditEventType.USER_LOGOUT,
            action_result=ActionResult.SUCCESS,
            actor=request.user,
            metadata={"channel": "API"},
            request=request
        )
        logout(request)
        return Response({"message": "Successfully logged out."})

class APIRegisterView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = UserRegisterSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        record_audit_event(
            event_type=AuditEventType.USER_REGISTERED,
            action_result=ActionResult.SUCCESS,
            actor=user,
            metadata={"role": user.role, "channel": "API"},
            request=self.request
        )

class APIUserListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_queryset(self):
        # Authenticated users can list active users to select recipients for sharing
        # If admin, list all including inactive
        if self.request.user.is_admin_role:
            return CustomUser.objects.all().order_by('username')
        return CustomUser.objects.filter(is_active=True).order_by('username')

class APIUserDetailView(generics.RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_queryset(self):
        if self.request.user.is_admin_role:
            return CustomUser.objects.all()
        return CustomUser.objects.filter(id=self.request.user.id)

class APICurrentUserView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)
