from django.shortcuts import render

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions,status
from  .serializers import RegisterUserSerializer
from django.contrib.auth import get_user_model


User = get_user_model()


class RegisterView(APIView):
    
    def post(self, request):
        
        data = request.data
        
        first_name = data["first_name"]
        last_name = data["last_name"]
        email = data["email"]
        password = data["password"]
        
        user= User.objects.create_user(first_name=first_name, last_name=last_name, email=email, password=password)
        user = RegisterUserSerializer(user)
        return Response(user.data,status=status.HTTP_201_CREATED)
    
    
class RetrieveUserView(APIView):
    
    pass
