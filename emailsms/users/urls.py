from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('about/', views.about, name='about'),
    path('profile/', views.profile, name='profile'),
    path('security/', views.security, name='security'),
    path('registration_dj/', views.registration_dj, name='registration_dj'),
    path('change_password_dj/', views.change_password_dj, name='change_password_dj'),
    path('register/', views.register_view, name='register'),
    path('login/', views.combined_login_view, name='combined_login'),
    path('logout/', views.combined_logout_view, name='combined_logout'),
    path('password-reset/', views.password_reset_view, name='password_reset'),
    path('toggle-theme/', views.toggle_theme, name='toggle_theme'),
]
