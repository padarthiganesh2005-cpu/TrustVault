from django import forms
from accounts.models import CustomUser
from .models import PermissionType

class GrantPermissionForm(forms.Form):
    user = forms.ModelChoiceField(
        queryset=CustomUser.objects.filter(is_active=True),
        widget=forms.Select(attrs={'class': 'form-select select2'}),
        empty_label="Select registered user...",
        help_text="Choose an active user to grant document access."
    )
    permission_type = forms.ChoiceField(
        choices=PermissionType.choices,
        widget=forms.Select(attrs={'class': 'form-select'}),
        initial=PermissionType.READ,
        help_text="Read allows viewing/downloading; Edit allows metadata edits and new version uploads."
    )

    def __init__(self, *args, document=None, **kwargs):
        super().__init__(*args, **kwargs)
        if document:
            # Exclude document owner and users who already have active permissions
            active_user_ids = document.permissions.filter(is_active=True).values_list('user_id', flat=True)
            self.fields['user'].queryset = CustomUser.objects.filter(
                is_active=True
            ).exclude(
                id=document.owner_id
            ).exclude(
                id__in=active_user_ids
            )
