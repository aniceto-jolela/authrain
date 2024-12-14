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
    path('login/', auth_views.LoginView.as_view(template_name='users/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(template_name='users/logout.html'), name='logout'),
    path('password-reset/', views.password_reset_view, name='password_reset'),
]
