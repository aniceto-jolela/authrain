from django.shortcuts import render, redirect
import requests
import os
from firebase_admin import auth as firebase_auth
from .forms import UserRegistrationForm, UserUpdate, ChangePasswordDj, User
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash, authenticate, login, logout as django_logout
from django.contrib.auth.views import LoginView
from .decorators import login_required_firebase, authenticated_home_required_firebase


# Your Firebase project's API key (found in your Firebase console under Project Settings -> General -> Web API Key)
FIREBASE_API_KEY = os.environ.get('FB_FIREBASE_API_KEY')
# FIREBASE
# EMAIL/PASSWORD


def register_view(request):
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')
        try:
            # Create a new user with email and password
            user = firebase_auth.create_user(
                email=email,
                password=password,
            )
            messages.success(request, f'Successful registered {user.email}!')
            return render(request, 'users/home.html', {'user': user})
        except Exception as e:
            return render(request, 'users/registration.html', {'error': str(e)})
    return render(request, 'users/registration.html', {'title': 'REGISTER'})


def password_reset_view(request):
    if request.method == "POST":
        email = request.POST.get('email')
        try:
            # Firebase Password Reset API Endpoint
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={FIREBASE_API_KEY}"
            payload = {
                "requestType": "PASSWORD_RESET",
                "email": email,
            }
            response = requests.post(url, json=payload)
            response_data = response.json()

            if response.status_code == 200:
                messages.success(request, 'An email has been sent to reset your password. Please check your inbox.')
                return render(request, 'users/home.html')  # Redirect to success page
            else:
                error_message = response_data.get('error', {}).get('message', 'Something went wrong.')
                return render(request, 'users/password_reset.html', {'error': error_message})
        except Exception as e:
            return render(request, 'users/password_reset.html', {'error': str(e)})
    return render(request, 'users/password_reset.html', {'title': 'PASSWORD RESET'})


# END EMAIL/PASSWORD


# DJANGO
# USER/PASSWORD
def registration_dj(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            user = form.cleaned_data.get('username')
            messages.success(request, f'{user} has been created!')
            return redirect('home')
    else:
        form = UserRegistrationForm()
    return render(request, 'users/registration_dj.html', {'form': form, 'title': 'REGISTRATION'})


@login_required_firebase
def profile(request):
    is_firebase_authenticated = request.session.get('is_firebase_authenticated', False)
    if request.method == 'POST':
        if 'django_profile' in request.POST:
            form = UserUpdate(request.POST, instance=request.user )
            if form.is_valid():
                try:
                    form.save()
                    user = form.cleaned_data.get('username')
                    messages.success(request, f'{user} updated successfully!')
                except Exception as e:
                    messages.error(request, f'An error occurred during update profile {e}')
        elif 'firebase_profile' in request.POST:
            firebase_uid = request.session.get('firebase_uid')  # Retrieve the user's Firebase UID from the session
            new_email = request.POST.get('new_email')

            if not firebase_uid:
                messages.error(request, 'User not authenticated with Firebase.')
                return redirect('combined_login')
            try:
                if request.session['is_firebase_email'] != new_email:
                    # Update email in Firebase
                    firebase_auth.update_user(firebase_uid, email=new_email)
                    request.session['is_firebase_email'] = new_email
                    messages.warning(request, 'This practice of redefining the email address is not recommended.')
                else:
                    messages.error(request, 'This email is already in use.')
                return redirect('profile')
            except Exception as e:
                messages.error(request, f'Error updating email: {str(e)}')
        return redirect('profile')
    else:
        form = ''
        is_firebase_email = request.session.get('is_firebase_email')
        if request.user.is_authenticated:
            form = UserUpdate(instance=request.user)
        context = {
            'form': form,
            'is_firebase_authenticated': is_firebase_authenticated,
            'title': 'PROFILE',
            'is_firebase_email': is_firebase_email
        }
        return render(request, 'users/profile.html', context)


def change_password_dj(request):
    if request.method == 'POST':
        form = ChangePasswordDj(request.user, request.POST)
        if form.is_valid():
            try:
                user = form.save()
                update_session_auth_hash(request, user)
                messages.success(request, f' Your password has been updated!')
                return redirect('profile')
            except Exception as e:
                messages.error(request, f'An error occurred during update profile {e}')
    else:
        form = ChangePasswordDj(request.user)
    return render(request, 'users/change_password_dj.html', {'form': form, 'title': 'PASSWORD RESET'})

# END USER/PASSWORD


# GLOBAL
class UserLoginView(LoginView):
    template_name = 'users/combined_login.html'

    def post(self, request, *args, **kwargs):
        if 'form' in request.POST:
            print(f'My tab1')
        elif request.POST.get('tab2') == 'tab2':
            print(f'My tab2.')
        return super().post(request, *args, **kwargs)


# ENDGLOBAL

@authenticated_home_required_firebase
def combined_login_view(request):
    if request.method == 'POST':
        if 'django_login' in request.POST:  # Django login form submitted
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('home')
            else:
                messages.error(request, 'Invalid Django username or password')

        elif 'firebase_login' in request.POST:  # Firebase login form submitted
            email = request.POST.get('email')
            password = request.POST.get('password')
            if not email or not password:
                messages.error(request, "Email and password are required.")
                return redirect('combined_login')

            # Firebase Authentication URL
            auth_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"

            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }

            # firebase_token = request.POST.get('firebase_token')
            try:
                # Make the request to Firebase
                response = requests.post(auth_url, json=payload)
                response_data = response.json()

                if 'idToken' in response_data:
                    # Successful login
                    firebase_token = response_data['idToken']
                    firebase_uid = response_data['localId']
                    email = response_data['email']

                    # Store in session
                    request.session['firebase_uid'] = firebase_uid
                    request.session['is_firebase_authenticated'] = True
                    request.session['is_firebase_email'] = email

                    messages.success(request, f"Successfully logged in via Firebase, {email}!.")
                    return redirect('home')
                else:
                    # Handle errors
                    error_message = response_data.get('error', {}).get('message', 'An error occurred')
                    messages.error(request, f"Login failed: {error_message}")
            except firebase_auth.UserNotFoundError:
                messages.error(request, 'Firebase email or password not found')
            except Exception as e:
                messages.error(request, str(e))

    return render(request, 'users/combined_login.html', {'title': 'LOGIN'})


def combined_logout_view(request):
    if request.method == 'POST':
        auth_type = request.POST.get('auth_type')  # Check which system to log out from

        if auth_type == 'django':  # Django logout
            django_logout(request)
            messages.success(request, "Successfully logged out from Django.")
        elif auth_type == 'firebase':  # Firebase logout
            try:
                # Invalidate Firebase user session by clearing token on client side.
                # Note: Firebase logout is typically handled client-side.
                request.session['is_firebase_authenticated'] = False
                messages.success(request, "Successfully logged out from Firebase.")
            except Exception as e:
                messages.error(request, f"Error logging out from Firebase: {e}")
        return redirect('combined_login')  # Redirect to login page
    return redirect('home')  # If accessed without POST, go to home


# BULMA XU
def toggle_theme(request):
    # Get the current theme from session (default to light mode)
    current_theme = request.session.get('theme', 'light')

    # Toggle theme
    new_theme = 'dark' if current_theme == 'light' else 'light'
    request.session['theme'] = new_theme  # Save new theme in session

    # Redirect to the previous page
    return redirect(request.META.get('HTTP_REFERER', '/'))
# ND BULMA


def home(request):
    is_firebase_authenticated = request.session.get('is_firebase_authenticated', False)
    context = {
        'title': 'HOME',
        'is_firebase_authenticated': is_firebase_authenticated
    }
    return render(request, 'users/home.html', context)


def about(request):
    is_firebase_authenticated = request.session.get('is_firebase_authenticated', False)
    context = {
        'title': 'ABOUT',
        'is_firebase_authenticated': is_firebase_authenticated
    }
    return render(request, 'users/about.html', context)


@login_required_firebase
def security(request):
    is_firebase_authenticated = request.session.get('is_firebase_authenticated', False)
    context = {
        'title': 'SECURITY',
        'is_firebase_authenticated': is_firebase_authenticated
    }
    return render(request, 'users/security.html', context)



