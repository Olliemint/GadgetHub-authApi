


from django.contrib.auth import authenticate, login,logout
from django.contrib.auth.hashers import make_password
from django.contrib.auth.forms import AuthenticationForm
from django.shortcuts import render, redirect
from django.contrib import messages

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions,status
from  .serializers import RegisterUserSerializer
from .forms import RegistrationForm
from .models import UserAccount
import jwt
from django.conf import settings
from django.contrib.auth import authenticate


class RegisterView(APIView):
    
    def post(self, request):
        
        data = request.data
        
        serializer =RegisterUserSerializer(data=data)
        
        if not serializer.is_valid():
            
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        
        user = serializer.create(serializer.validated_data)
        
        user = RegisterUserSerializer(user)
        return Response(user.data,status=status.HTTP_201_CREATED)
    
    
class LoginView(APIView):
    def post(self, request, format=None):
        email = request.data.get('email')
        password = request.data.get('password')
        email=email.lower()
        user = authenticate(request, username=email, password=password)

        if user is not None:
            payload = {
                'user_id': user.id,
                'email': user.email
            }
            token = jwt.encode(payload, settings.SECRET_KEY)
            return Response({'token': token}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)
    
    
    
    
def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('home')
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})



def logout_view(request):
    logout(request)
    return redirect('login')


def register_view(request,min_length=8):
        if request.method == 'POST':
            email = request.POST['email']
            first_name = request.POST['first_name']
            last_name = request.POST['last_name']
            
        
            password = request.POST['password']
            
            
        
        
            if len(password) > min_length:
                
                if UserAccount.objects.filter(email=email).exists():
                    messages.info(request,'Email already exists')
                    return redirect('signup')
                
               
                
                else:
                    # hashed_password = make_password('password')
                    user = UserAccount.objects.create_user(first_name=first_name,last_name =last_name,email=email,password=password)
                    user.save()
                    # user_model = UserAccount.objects.get(username=username)
                    # new_profile = Profile.objects.create(user=user_model,id_user=user_model.id)
                    return redirect('login')

                    
            else:
                messages.info(request,'Password length mismatch')  
                return redirect('signup')
    
        return render(request, 'register.html')


def home_view(request):
    return render(request, 'home.html')
    
    
    

