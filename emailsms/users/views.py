from django.shortcuts import render, redirect
import requests
import os
from firebase_admin import auth
from .forms import UserRegistrationForm, UserUpdate, ChangePasswordDj
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.views.generic import (
    UpdateView
)


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
            user = auth.create_user(
                email=email,
                password=password,
            )
            return render(request, 'users/registration_success.html', {'user': user})
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
                return render(request, 'users/password_reset_done.html')  # Redirect to success page
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


@login_required
def profile(request):
    if request.method == 'POST':
        form = UserUpdate(request.POST, instance=request.user )
        if form.is_valid():
            try:
                form.save()
                user = form.cleaned_data.get('username')
                messages.success(request, f'{user} updated successfully!')
            except Exception as e:
                messages.error(request, f'An error occurred during update profile {e}')
    else:
        form = UserUpdate(instance=request.user)
    context = {
        'form': form,
        'title': 'PROFILE',
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
                return redirect('login')
            except Exception as e:
                messages.error(request, f'An error occurred during update profile {e}')
    else:
        form = ChangePasswordDj(request.user)
    return render(request, 'users/change_password_dj.html', {'form': form, 'title': 'PASSWORD RESET'})

# END USER/PASSWORD


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
    return render(request, 'users/home.html', {'title': 'HOME'})


def about(request):
    return render(request, 'users/about.html', {'title': 'ABOUT'})


@login_required
def security(request):
    return render(request, 'users/security.html', {'title': 'SECURITY'})



