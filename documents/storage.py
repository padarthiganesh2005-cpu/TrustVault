import os
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.core.exceptions import SuspiciousFileOperation

class PrivateFileSystemStorage(FileSystemStorage):
    """
    Private file system storage for confidential documents.
    Features:
      1. Strictly stores files inside PRIVATE_MEDIA_ROOT.
      2. base_url is None to prevent accidental generation of public web URLs.
      3. Overrides .url() to prevent URL generation.
      4. Hardens paths against directory traversal.
    """
    def __init__(self, *args, **kwargs):
        kwargs['location'] = str(settings.PRIVATE_MEDIA_ROOT)
        kwargs['base_url'] = None
        super().__init__(*args, **kwargs)

    def url(self, name):
        raise SuspiciousFileOperation(
            "Direct public URLs are prohibited for private documents. "
            "Use the authorized download endpoint /documents/<id>/download/ instead."
        )

private_storage = PrivateFileSystemStorage()
