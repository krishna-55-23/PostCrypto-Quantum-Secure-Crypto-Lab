from django.urls import path
from . import views

urlpatterns = [
    #path('', views.base, name="base"),
    path('', views.dashboard, name="dashboard"),
    path('experiment/', views.experiment, name="experiment"),
    path('analytics/', views.analytics, name="analytics"),
    path('secure/', views.secure_message, name="secure"),
    path('analytics/delete/<int:pk>/', views.delete_log,   name="delete_log"),

]