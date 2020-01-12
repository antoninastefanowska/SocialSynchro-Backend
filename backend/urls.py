from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^post_twitter_verifier$', views.post_twitter_verifier, name = 'Sign in'),
    url(r'^get_twitter_verifier$', views.get_twitter_verifier, name = 'Sign in'),
    url(r'^post_facebook_token$', views.post_facebook_token, name = 'Sign in'),
    url(r'^get_facebook_token$', views.get_facebook_token, name = 'Sign in'),
    url(r'^post_deviantart_code$', views.post_deviantart_code, name = 'Sign in'),
    url(r'^get_deviantart_code$', views.get_deviantart_code, name = 'Sign in'),
    url(r'^get_rate_limits$', views.get_rate_limits, name = 'Get rate limits'),
    url(r'^update_request_counter$', views.update_request_counter, name = 'Update request counter'),
    url(r'^privacy_policy$', views.privacy_policy, name = 'Privacy Policy'),
]