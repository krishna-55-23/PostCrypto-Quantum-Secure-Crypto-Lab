from django.db import models
from django.contrib.auth.models import User

class CryptoExperiment(models.Model):
    #user = models.ForeignKey(User, on_delete=models.CASCADE)
    user = models.CharField(max_length=50, default="guest")
    
    algorithm = models.CharField(max_length=50)

    key_generation_time = models.FloatField()
    encryption_time = models.FloatField()

    key_size = models.IntegerField()
    message_size = models.IntegerField()

    generated_key = models.TextField()
    encrypted_message = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return f"{self.algorithm} - {self.user}"
    
# Create your models here.
