from django.db import models

from django.contrib.auth.models import BaseUserManager, AbstractBaseUser,PermissionsMixin



class UserAccountManager(BaseUserManager):
    def create_user(self, email,first_name,last_name, password=None):
        
        if not email:
            raise ValueError('Users must have an email address')
        
        email= self.normalize_email(email)
        

        user = self.model(
            first_name=first_name,
            last_name=last_name,
            email=email
            
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email,first_name,last_name, password=None):
        
        user = self.create_user(
            email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user
    


class UserAccount(AbstractBaseUser,PermissionsMixin):
    email = models.EmailField(max_length=255,unique=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserAccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.email

   

    