# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from django.core.validators import MinLengthValidator
from django.utils import timezone

from . import config

class ApplicationKey(models.Model):
    application_name = models.CharField(default = config.APPLICATION_NAME, max_length = 20, unique = True, blank = False, null = False)
    consumer_key = models.CharField(max_length = config.CONSUMER_KEY_LENGTH, unique = True, blank = False, null = False)
    secret_consumer_key = models.CharField(max_length = config.SECRET_CONSUMER_KEY_LENGTH, blank = False, null = False)

class TwitterToken(models.Model):
    request_token = models.CharField(validators = [MinLengthValidator(27)], max_length = 27, unique = True, blank = False, null = False)
    verifier = models.CharField(validators = [MinLengthValidator(32)], max_length = 32, blank = False, null = False)

class FacebookToken(models.Model):
    state = models.CharField(validators = [MinLengthValidator(30)], max_length = 30, unique = True, blank = False, null = False)
    token = models.CharField(max_length = 200, blank = False, null = False)

class DeviantArtToken(models.Model):
    state = models.CharField(validators = [MinLengthValidator(30)], max_length = 30, unique = True, blank = False, null = False)
    code = models.CharField(max_length = 200, blank = False, null = False)

class RequestCounter(models.Model):
    endpoint = models.CharField(max_length = 50, unique = True, blank = False, null = False)
    service_name = models.CharField(max_length = 50, blank = False, null = False)
    init_date = models.DateTimeField(default = timezone.now)
    reset_window = models.IntegerField(null = True)
    limit = models.IntegerField(null = True)
    remaining = models.IntegerField(null = True)
    reset = models.IntegerField(null = True)

    def reset_counter(self):
        self.remaining = self.limit
        self.reset = self.reset_window
