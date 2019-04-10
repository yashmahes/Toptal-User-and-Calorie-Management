from django.contrib import admin
from django.urls import path, include
from users import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('register/', views.Register.as_view()),
    path('logout/', views.Logout.as_view()),
    path('users/', views.MyUsers.as_view()),
    path('users/<u_id>', views.MyUsers.as_view()),
    #path('^users/(?P<u_id>\d+)', views.MyUsers.as_view()),
    path('login/', views.Login.as_view()),
    path('myprofile/', views.Myprofile.as_view()),
    path('addcalorie/', views.CalorieEntryView.as_view()),
    path('calorie/', views.CalorieEntryView.as_view()),
    path('calorie/<id>', views.CalorieEntryView.as_view()),
    path('verifyregistration/<access_token>',
         views.VerifyRegistration.as_view()),
    path('sendinvite/', views.SendInvite.as_view()),
    path('forgotpassword/', views.ForgotPasswordView.as_view()),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)
