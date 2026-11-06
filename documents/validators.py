import os
import re
import filetype
from django.conf import settings
from django.core.exceptions import ValidationError

DANGEROUS_EXTENSIONS = {
    '.exe', '.dll', '.so', '.bin', '.bat', '.cmd', '.sh', '.bash',
    '.ps1', '.vbs', '.js', '.jsx', '.ts', '.php', '.phtml', '.py',
    '.rb', '.pl', '.cgi', '.asp', '.aspx', '.jsp', '.jar', '.war',
    '.scr', '.pif', '.com', '.msi', '.msp', '.hta', '.cpl'
}

ALLOWED_EXTENSIONS = set(settings.ALLOWED_FILE_EXTENSIONS)

def sanitize_filename(filename: str) -> str:
    """
    Sanitize uploaded filename:
      1. Strip directory traversal tokens ('..', '/', '\\').
      2. Remove null bytes and non-printable characters.
      3. Normalize spaces to underscores.
    """
    if not filename:
        return "unnamed_document"
    # Remove path components
    filename = os.path.basename(filename)
    # Remove null bytes
    filename = filename.replace('\x00', '').replace('%00', '')
    # Replace dangerous characters with underscores
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    # Collapse consecutive dots or underscores
    filename = re.sub(r'\.{2,}', '.', filename)
    filename = re.sub(r'_{2,}', '_', filename)
    return filename.strip('._') or "unnamed_document"

def validate_file_upload(file_obj):
    """
    Comprehensive multi-layer security validation for uploaded files:
      1. Empty file detection.
      2. File size limit enforcement.
      3. Path traversal detection in original name.
      4. Double extension and dangerous extension attacks.
      5. File header magic bytes inspection (content signature verification).
      6. Executable and binary payload rejection for text files.
    """
    # 1. Size Check
    if file_obj.size == 0:
        raise ValidationError("Uploaded file is empty (0 bytes).")

    if file_obj.size > settings.MAX_UPLOAD_SIZE:
        max_mb = settings.MAX_UPLOAD_SIZE / (1024 * 1024)
        raise ValidationError(f"File size exceeds maximum permitted limit of {max_mb:.0f} MB.")

    original_name = file_obj.name or ''

    # 2. Path Traversal & Null Byte Check
    if any(pattern in original_name for pattern in ['../', '..\\', '\x00', '%00']):
        raise ValidationError("Filename contains illegal directory traversal or null byte sequences.")

    # 3. Extension Validation
    _, ext = os.path.splitext(original_name)
    ext = ext.lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise ValidationError(
            f"File extension '{ext}' is not permitted. Allowed extensions: {', '.join(sorted(ALLOWED_EXTENSIONS))}."
        )

    # 4. Double-Extension Detection
    # Example: 'invoice.pdf.exe' or 'report.exe.pdf'
    parts = original_name.lower().split('.')
    if len(parts) > 2:
        inner_extensions = [f".{p}" for p in parts[1:-1]]
        for inner_ext in inner_extensions:
            if inner_ext in DANGEROUS_EXTENSIONS:
                raise ValidationError(
                    f"Suspicious double-extension detected containing dangerous token '{inner_ext}'."
                )

    # 5. Magic Bytes / Signature Validation
    # Read first 2048 bytes for signature detection
    file_obj.seek(0)
    header = file_obj.read(2048)
    file_obj.seek(0)

    # Immediate rejection if starts with Windows PE or ELF or Mach-O executable header
    if header.startswith(b'MZ') or header.startswith(b'\x7fELF') or header.startswith(b'\xca\xfe\xba\xbe'):
        raise ValidationError("Security violation: Binary executable signature detected.")

    # Signature verification by extension
    if ext == '.pdf':
        if not header.startswith(b'%PDF-'):
            raise ValidationError("File content signature does not match valid PDF specification.")
    elif ext == '.png':
        if not header.startswith(b'\x89PNG\r\n\x1a\n'):
            raise ValidationError("File content signature does not match valid PNG specification.")
    elif ext in ('.jpg', '.jpeg'):
        if not header.startswith(b'\xff\xd8\xff'):
            raise ValidationError("File content signature does not match valid JPEG specification.")
    elif ext in ('.docx', '.xlsx'):
        # OpenXML documents are ZIP archives beginning with PK\x03\x04
        if not header.startswith(b'PK\x03\x04'):
            raise ValidationError(f"File content signature does not match valid Office OpenXML ({ext}) format.")
    elif ext in ('.txt', '.csv'):
        # Verify text is decodeable and not binary or script
        try:
            sample_text = header.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            try:
                sample_text = header.decode('latin-1', errors='strict')
            except Exception:
                raise ValidationError("Plain text file contains invalid non-text characters.")
        # Check for scripting injection in text files
        lower_sample = sample_text.lower()
        if '<script' in lower_sample or 'javascript:' in lower_sample or sample_text.startswith('#!'):
            raise ValidationError("File content contains prohibited script or executable directives.")

    # Reset file pointer to beginning for subsequent saving
    file_obj.seek(0)
    return True
