from firebase_admin import auth as firebase_auth


def validate_firebase_token(request):
    firebase_token = request.COOKIES.get('firebase_token')
    if firebase_token:
        try:
            decoded_token = firebase_auth.verify_id_token(firebase_token)
            request.session['is_firebase_authenticated'] = True
            request.session['firebase_uid'] = decoded_token.get('uid')
        except Exception as e:
            request.session['is_firebase_authenticated'] = False