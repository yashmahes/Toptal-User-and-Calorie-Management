from rest_framework import exceptions
from rest_framework import authentication
import random
from django.contrib.auth.hashers import check_password, make_password
from django.core.cache import cache
from django.conf import settings
from mysite.settings import db


class LoginAuthentication(authentication.BaseAuthentication):

    def authenticate(self, request, token=None):
        try:
            token = request.META.get('HTTP_AUTHORIZATION')

            if token:
                token_array = token.split(' ')

                user = db.user.find_one({'access_token': token_array[1]})

                if user:
                    return (user, None)  # authentication successful
                else:
                    raise exceptions.AuthenticationFailed(
                        'Authentication Failed. Please login to use this API.')

            else:
                raise exceptions.AuthenticationFailed(
                    'Authentication Failed. Please login to use this API.')
        except:
            # raise exception if user does not exist
            raise exceptions.AuthenticationFailed(
                'Authentication Failed. Please login to use this API.')

        return (user, None)  # authentication successful


def get_user_from_token(request):
    token = request.META.get('HTTP_AUTHORIZATION')
    token_array = token.split(' ')

    user = db.user.find_one({'access_token': token_array[1]})
    return user
