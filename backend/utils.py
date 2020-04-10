import random
import string

from .models import ApplicationKey, RequestCounter
from . import config

def generate_key(length):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def generate_application_keys():
    consumer_key = generate_key(config.CONSUMER_KEY_LENGTH)
    secret_consumer_key = generate_key(config.SECRET_CONSUMER_KEY_LENGTH)
    try:
        application_key = ApplicationKey.objects.get(application_name = config.APPLICATION_NAME)
        application_key.consumer_key = consumer_key
        application_key.secret_consumer_key = secret_consumer_key
    except ApplicationKey.DoesNotExist:
        application_key = ApplicationKey(application_name = config.APPLICATION_NAME, consumer_key = consumer_key, secret_consumer_key = secret_consumer_key)

    application_key.save()
    print('Consumer key: ' + consumer_key + ' Secret consumer key: ' + secret_consumer_key)

def initialize_database_data():
    update_status, created = RequestCounter.objects.get_or_create(endpoint = '/statuses/update', service_name = config.TWITTER_SERVICE_NAME)
    update_status.limit = config.TWITTER_UPDATE_STATUS_LIMIT
    update_status.reset_window = config.TWITTER_RESET_UPDATE_STATUS_SECONDS
    update_status.remaining = config.TWITTER_UPDATE_STATUS_LIMIT
    update_status.reset = config.TWITTER_RESET_UPDATE_STATUS_SECONDS
    update_status.save()

    destroy_status, created = RequestCounter.objects.get_or_create(endpoint = '/statuses/destroy/:id', service_name = config.TWITTER_SERVICE_NAME)
    destroy_status.limit = config.TWITTER_DESTROY_STATUS_LIMIT
    destroy_status.reset_window = config.TWITTER_RESET_DESTROY_STATUS_SECONDS
    destroy_status.remaining = config.TWITTER_DESTROY_STATUS_LIMIT
    destroy_status.reset = config.TWITTER_RESET_DESTROY_STATUS_SECONDS
    destroy_status.save()