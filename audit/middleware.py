import threading

_thread_locals = threading.local()

def get_current_request():
    """Retrieve the current thread's HTTP request."""
    return getattr(_thread_locals, 'request', None)

def get_current_user():
    """Retrieve the authenticated user from the current request thread."""
    request = get_current_request()
    if request and hasattr(request, 'user') and request.user.is_authenticated:
        return request.user
    return None

def get_client_ip(request) -> str:
    """Safely extract the client IP address from the request."""
    if not request:
        return '127.0.0.1'
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    return ip

class AuditRequestMiddleware:
    """
    Middleware that captures request context (IP, user agent, user)
    into thread-local storage so that audit services throughout the application
    can access forensic metadata seamlessly.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        _thread_locals.request = request
        response = self.get_response(request)
        _thread_locals.request = None
        return response
