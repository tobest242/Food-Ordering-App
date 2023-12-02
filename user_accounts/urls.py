from django.urls import path
from .views import RegisterUserView, VerifyUserEmail, LoginView, TestAuthentcationView, PasswordResetConfirm, PasswordResetRequestView, SetNewPasswordView

urlpatterns = [
    path('register/', RegisterUserView.as_view(), name='register'),
    path('verify-email/', VerifyUserEmail.as_view(), name='verify'),
    path('login/', LoginView.as_view(), name='login'),
    path('test/', TestAuthentcationView.as_view(), name='test'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirm.as_view(), name='password-reste-confirm'),
    path('set-new-password/', SetNewPasswordView.as_view(), name='set-new-password')
]
