# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import IntegrityError
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render

import hmac
import hashlib
import base64
import logging

from .models import ApplicationKey, TwitterToken, FacebookToken, DeviantArtToken, RequestCounter
from . import config

logger = logging.getLogger(__name__)

def index(request):
    return render(request, 'backend/redirect.html', { 'message' : 'SocialSynchro' })

def authorize_request(request):
    try:
        if not 'Authorization' in request.headers.keys():
            return { 'success' : False, 'message' : 'Authorization failed. No authorization header.' }

        authorization_string = request.headers['Authorization']

        authorization_parameters = dict(parameter.split("=") for parameter in authorization_string.split("&"))
        received_consumer_key = authorization_parameters["consumer_key"]
        application_key = ApplicationKey.objects.get(consumer_key = received_consumer_key)

        received_timestamp = authorization_parameters["timestamp"]
        current_timestamp = timezone.now().timestamp()
        if current_timestamp - int(received_timestamp) > config.REQUEST_EXPIRATION_TIME_SECONDS:
            return { 'success' : False, 'message' : 'Authorization failed. Request expired.' }

        received_signature = authorization_parameters["signature"]
        secret_consumer_key = application_key.secret_consumer_key

        hash_input = received_timestamp + received_consumer_key
        raw_hash_input = bytes(hash_input, encoding = "utf-8")
        raw_key = bytes(secret_consumer_key, encoding = "utf-8")
        raw_calculated_signature = hmac.new(raw_key, raw_hash_input, hashlib.sha1).digest()
        calculated_signature = base64.b64encode(raw_calculated_signature).decode()
        calculated_signature = calculated_signature[:-1]

        if received_signature != calculated_signature:
            return { 'success' : False, 'message' : 'Authorization failed. Incorrect signature.' }

        return { 'success' : True, 'message' : 'Authorization successful.' }

    except ApplicationKey.DoesNotExist:
        return { 'success' : False, 'message' : 'Authorization failed. Incorrect consumer key.' }

    except KeyError:
        return { 'success' : False, 'message' : 'Authorization failed. Incorrect authorization parameters.' }


def post_twitter_verifier(request):
    try:
        request_token = request.GET.get('oauth_token')
        verifier = request.GET.get('oauth_verifier')
        twitter_token = TwitterToken(request_token = request_token, verifier = verifier)
        twitter_token.save()
        return render(request, 'backend/redirect.html', { 'message' : 'Login successful! Return to application and confirm.' })

    except IntegrityError:
        return render(request, 'backend/redirect.html', { 'message' : 'Incorrect token.' })

def get_twitter_verifier(request):
    try:
        authorization_result = authorize_request(request)
        if authorization_result['success'] == False:
            return JsonResponse({ 'message' : authorization_result['message'] }, status = 401)

        request_token = request.GET.get('oauth_token')
        twitter_token = TwitterToken.objects.get(request_token = request_token)
        response = {
            'oauth_token' : twitter_token.request_token,
            'oauth_verifier' : twitter_token.verifier
        }
        twitter_token.delete()
        return JsonResponse(response, status = 200)

    except TwitterToken.DoesNotExist:
        return JsonResponse({ 'message' : 'Token not found (could be expired).' }, status = 404)

    except Exception as e:
        return JsonResponse({ 'message' : 'Unexpected error: ' + str(e) }, status = 500)

def post_facebook_token(request):
    reloaded = False;
    try:
        if 'reloaded' in request.session:
            reloaded = request.session['reloaded']

        state = request.GET.get('state')
        token = request.GET.get('access_token')
        facebook_token = FacebookToken(state = state, token = token)
        facebook_token.save()
        request.session['reloaded'] = False;
        return render(request, 'backend/redirect.html', { 'message' : 'Login successful! Return to application and confirm.' })

    except IntegrityError:
        if not reloaded:
            request.session['reloaded'] = True;
            return render(request, 'backend/redirect.html', { 'message' : 'Reloading...' });
        else:
            return render(request, 'backend/redirect.html', { 'message' : 'Incorrect token.'})

def get_facebook_token(request):
    try:
        authorization_result = authorize_request(request)
        if authorization_result['success'] == False:
            return JsonResponse({ 'message' : authorization_result['message'] }, status = 401)

        state = request.GET.get('state')
        facebook_token = FacebookToken.objects.get(state = state)
        response = {
            'state' : facebook_token.state,
            'token' : facebook_token.token
        }
        facebook_token.delete()
        return JsonResponse(response, status = 200)

    except FacebookToken.DoesNotExist:
        return JsonResponse({ 'message' : 'Token not found (could be expired).' }, status = 404)

    except Exception as e:
        return JsonResponse({ 'message' : 'Unexpected error: ' + str(e) }, status = 500)

def post_deviantart_code(request):
    try:
        state = request.GET.get('state')
        code = request.GET.get('code')
        deviantart_token = DeviantArtToken(state = state, code = code)
        deviantart_token.save()
        return render(request, 'backend/redirect.html', { 'message' : 'Login successful! Return to application and confirm.' })

    except IntegrityError:
        return render(request, 'backend/redirect.html', { 'message' : 'Incorrect token.' })

def get_deviantart_code(request):
    try:
        authorization_result = authorize_request(request)
        if authorization_result['success'] == False:
            return JsonResponse({ 'message' : authorization_result['message'] }, status = 401)

        state = request.GET.get('state')
        deviantart_token = DeviantArtToken.objects.get(state = state)
        response = {
            'state' : deviantart_token.state,
            'code' : deviantart_token.code
        }
        deviantart_token.delete()
        return JsonResponse(response, status = 200)

    except DeviantArtToken.DoesNotExist:
        return JsonResponse({ 'message' : 'Token not found (could be expired).' }, status = 404)

    except Exception as e:
        return JsonResponse({ 'message' : 'Unexpected error: ' + str(e) }, status = 500)

def get_rate_limits(request):
    try:
        endpoint = request.GET.get('endpoint')
        service_name = request.GET.get('service_name')
        request_counter = RequestCounter.objects.get(endpoint = endpoint, service_name = service_name)

        remaining = request_counter.remaining

        if remaining < request_counter.limit:
            init_date = request_counter.init_date
            current_date = timezone.now()
            elapsed = int((current_date - init_date).total_seconds())

            if elapsed > request_counter.reset_window:
                request_counter.reset_counter()
            else:
                request_counter.reset = request_counter.reset_window - elapsed
                if remaining == 0:
                    logger.info(str(current_date) + ' ' + service_name + ' ' + endpoint + ' request rate exceeded.')
            request_counter.save()

        response = {
            'remaining' : remaining,
            'reset' : request_counter.reset
        }
        return JsonResponse(response, status = 200)

    except RequestCounter.DoesNotExist:
        return JsonResponse({ 'message' : 'No such request.' }, status = 404)

    except Exception as e:
        return JsonResponse({ 'message' : 'Unexpected error: ' + str(e) }, status = 500)

@csrf_exempt
def update_request_counter(request):
    try:
        authorization_result = authorize_request(request)
        if authorization_result['success'] == False:
            return JsonResponse({ 'message' : authorization_result['message'] }, status = 401)

        endpoint = request.POST.get('endpoint')
        service_name = request.POST.get('service_name')
        request_counter = RequestCounter.objects.get(endpoint = endpoint, service_name = service_name)

        remaining = request_counter.remaining
        if remaining > 0:
            if remaining == request_counter.limit:
                request_counter.init_date = timezone.now()
            request_counter.remaining = remaining - 1
            request_counter.save()

        return JsonResponse({ }, status = 200)

    except RequestCounter.DoesNotExist:
        return JsonResponse({ 'message' : 'No such request. ' + endpoint + ' ' + service_name }, status = 404)

    except Exception as e:
        return JsonResponse

def privacy_policy(request):
    return render(request, 'backend/privacy_policy.html', { })