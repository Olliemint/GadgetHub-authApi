from django.urls import path
from . import views


urlpatterns = [
    path("",views.home_view,name="home"),
    path('signup/', views.RegisterView.as_view(),name="signup"),
    path('login/', views.LoginView.as_view(),name="login"),
    path('logout/', views.logout_view,name="logout"),
    
]