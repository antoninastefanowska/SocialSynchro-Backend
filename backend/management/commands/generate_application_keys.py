import random
import string

from django.core.management.base import BaseCommand
from backend.models import ApplicationKey
from backend import config

class Command(BaseCommand):
    help = "generating application keys"

    def generate_key(length):
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

    def handle(self, *args, **options):
        self.consumer_key = self.generate_key(config.CONSUMER_KEY_LENGTH)
        self.secret_consumer_key = self.generate_key(config.SECRET_CONSUMER_KEY_LENGTH)
        try:
            self.application_key = ApplicationKey.objects.get(application_name = config.APPLICATION_NAME)
            self.application_key.consumer_key = self.consumer_key
            self.application_key.secret_consumer_key = self.secret_consumer_key
        except ApplicationKey.DoesNotExist:
            self.application_key = ApplicationKey(application_name = config.APPLICATION_NAME, consumer_key = self.consumer_key, secret_consumer_key = self.secret_consumer_key)

        self.application_key.save()
        print('Consumer key: ' + self.consumer_key + ' Secret consumer key: ' + self.secret_consumer_key)