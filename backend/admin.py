# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from .models import ApplicationKey, TwitterToken, FacebookToken, RequestCounter

admin.site.register(ApplicationKey)
admin.site.register(TwitterToken)
admin.site.register(FacebookToken)
admin.site.register(RequestCounter)

class Administrator(UserAdmin):
    model = User
    list_display = ['username']