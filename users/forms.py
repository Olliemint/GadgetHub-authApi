from django import forms
from .models import UserAccount
from django.contrib.auth import authenticate, login,logout
from django.shortcuts import render, redirect

class RegistrationForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)
    password_confirm = forms.CharField(widget=forms.PasswordInput)

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if UserAccount.objects.filter(email=email).exists():
            raise forms.ValidationError(
                'A user with that email already exists')
        return email

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')
        if password != password_confirm:
            raise forms.ValidationError('Passwords do not match')

    def register(request):
        if request.method == 'POST':
            form = RegistrationForm(request.POST)
            if form.is_valid():
                email = form.cleaned_data.get('email')
                password = form.cleaned_data.get('password')
                UserAccount.objects.create_user(email=email, password=password)
                user = authenticate(email=email, password=password)
                login(request, user)
                return redirect('home')
        else:
            form = RegistrationForm()
       