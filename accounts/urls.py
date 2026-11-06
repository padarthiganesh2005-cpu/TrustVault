from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    # Web UI URLs
    path('profile/', views.profile_view, name='profile'),
    path('users/', views.user_management_view, name='user_management'),
    path('users/<int:user_id>/toggle-status/', views.toggle_user_status_view, name='toggle_user_status'),

    # REST API endpoints
    path('api/auth/login/', views.APILoginView.as_view(), name='api_login'),
    path('api/auth/logout/', views.APILogoutView.as_view(), name='api_logout'),
    path('api/auth/register/', views.APIRegisterView.as_view(), name='api_register'),
    path('api/users/', views.APIUserListView.as_view(), name='api_user_list'),
    path('api/users/me/', views.APICurrentUserView.as_view(), name='api_user_me'),
    path('api/users/<int:pk>/', views.APIUserDetailView.as_view(), name='api_user_detail'),
]
