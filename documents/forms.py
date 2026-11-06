from django import forms
from .models import Document, DocumentCategory, DocumentVersion
from .validators import validate_file_upload

class DocumentUploadForm(forms.ModelForm):
    file = forms.FileField(
        required=True,
        widget=forms.ClearableFileInput(attrs={'class': 'form-control'}),
        help_text="Allowed formats: PDF, DOCX, XLSX, TXT, PNG, JPG, CSV. Max size: 25 MB."
    )

    class Meta:
        model = Document
        fields = ('name', 'description', 'category', 'tags', 'file')
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter clear document title'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Provide document summary or purpose'}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'tags': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'finance, confidential, q3-audit'}),
        }

    def clean_file(self):
        f = self.cleaned_data.get('file')
        if f:
            validate_file_upload(f)
        return f

class DocumentEditForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ('name', 'description', 'category', 'tags')
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'tags': forms.TextInput(attrs={'class': 'form-control'}),
        }

class DocumentVersionReplaceForm(forms.Form):
    file = forms.FileField(
        required=True,
        widget=forms.ClearableFileInput(attrs={'class': 'form-control'}),
        help_text="Upload replacement document version. Max size: 25 MB."
    )
    change_summary = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 2, 'placeholder': 'Describe changes in this revision'}),
        help_text="Summary of revision changes for the audit trail."
    )

    def clean_file(self):
        f = self.cleaned_data.get('file')
        if f:
            validate_file_upload(f)
        return f
