from functools import wraps
from django.shortcuts import redirect


# decorator to check for either Django or Firebase authentication.
def login_required_firebase(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated and not request.session.get('is_firebase_authenticated', False):
            return redirect('combined_login')  # Redirect to your login page
        return view_func(request, *args, **kwargs)

    return _wrapped_view


def authenticated_home_required_firebase(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated or request.session.get('is_firebase_authenticated', False):
            return redirect('home')  # Redirect to your home page
        return view_func(request, *args, **kwargs)

    return _wrapped_view
