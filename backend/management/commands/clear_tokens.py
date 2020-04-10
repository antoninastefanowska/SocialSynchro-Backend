from django.core.management.base import BaseCommand
from backend.models import TwitterToken, FacebookToken

class Command(BaseCommand):
    help = "clearing tokens"
    def handle(self, *args, **options):
        TwitterToken.objects.all().delete()
        FacebookToken.objects.all().delete()