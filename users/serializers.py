from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import get_user_model
from django.core import exceptions

User = get_user_model()


class RegisterUserSerializer(serializers.ModelSerializer):
    
    class Meta:
        model= User
        fields = ("first_name", "last_name", "email", "password")

    
    def validate(self, data):
         
        user = User(**data)
        password = data.get('password')
        
        try:
            validate_password(user,password)
        except exceptions.ValidationError as e:
            serializer_error = serializers.as_serializer_error(e)
            raise exceptions.ValidationError(
                {'password': serializer_error['non_field_errors']}
            )
            
        return user
    
    def create(self, validated_data):
        user = User.objects.create_user(
            first_name = validated_data['first_name'],
            last_name = validated_data['last_name'],
            email = validated_data['email'],
            password = validated_data['password']
        )
        
        
        return user