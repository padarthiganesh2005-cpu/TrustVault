from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import CustomUser, UserRole

class CustomLoginForm(AuthenticationForm):
    username = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control form-control-lg', 'placeholder': 'Username or Email', 'autocomplete': 'username'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control form-control-lg', 'placeholder': 'Password', 'autocomplete': 'current-password'})
    )

class UserRegisterForm(UserCreationForm):
    role = forms.ChoiceField(
        choices=[(UserRole.OWNER, 'Document Owner (Can upload & share)'), (UserRole.VIEWER, 'Viewer (Read-only on shared documents)')],
        widget=forms.Select(attrs={'class': 'form-select'}),
        initial=UserRole.VIEWER,
        help_text="Choose your role in TrustVault."
    )
    department = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. Legal, Finance, Engineering'})
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'name@company.com'})
    )

    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'department', 'role')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            if not isinstance(field.widget, forms.Select):
                field.widget.attrs.update({'class': 'form-control'})

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ('first_name', 'last_name', 'email', 'department')
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'department': forms.TextInput(attrs={'class': 'form-control'}),
        }

class AdminUserManagementForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ('role', 'department', 'is_active')
        widgets = {
            'role': forms.Select(attrs={'class': 'form-select'}),
            'department': forms.TextInput(attrs={'class': 'form-control'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }
