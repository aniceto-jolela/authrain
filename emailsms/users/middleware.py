# users/middleware.py
from django.utils.deprecation import MiddlewareMixin
from firebase_admin import auth as firebase_auth
# from .utils import validate_firebase_token


class FirebaseAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # validate_firebase_token(request)
        if not request.user.is_authenticated:
            firebase_token = request.COOKIES.get('firebase_token')
            if firebase_token:
                try:
                    decoded_token = firebase_auth.verify_id_token(firebase_token)
                    firebase_uid = decoded_token.get('uid')

                    # Optionally, sync Firebase user with Django User model
                    request.session['is_firebase_authenticated'] = True
                    request.session['firebase_uid'] = firebase_uid
                except Exception as e:
                    request.session['is_firebase_authenticated'] = False
        else:
            request.session['is_firebase_authenticated'] = False

