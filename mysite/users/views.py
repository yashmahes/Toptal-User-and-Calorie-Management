import datetime
import urllib
import logging
import json
import pytz
import uuid
import os
from django.http import HttpResponse  # pylint: disable=unused-import
from mysite import settings
from mysite.settings import db, BASE_DIR
import time
from PIL import Image
from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.views import APIView
from bson.objectid import ObjectId
# from common.decorators import requires_auth
# from common.sessionhelper import authenticate_api_user, cache_public_key, get_user_from_token, delete_public_key
from common.messages import REGISTERED_SUCCESSFULLY, INVALID_DETAIL, USER_JOIN, USER_JOIN_MESSAGE, \
    USER_LOGGED_IN, USER_LOGGED_IN_MESSAGE, RESET_PASSWORD_EMAIL, FORGOT_PASSWORD, FORGOT_PASSWORD_MESSAGE, \
    INTERNAL_SERVER_ERROR, USER_LOGGED_OUT, USER_LOGGED_OUT_MESSAGE, LOGGED_OUT_SUCCESS, REFRESH_TOKEN_EXPIRED
# from common.datamodel import response_data_encryption, email_password_reset, get_image_url, \
#  get_acccess_and_refresh_token, decode_access_token

from users.serializers import RegisterSerializer, LoginSerializer, ForgotPasswordSerializer,CalorieEntrySerializer
from common.sessionhelper import get_user_from_token
from django.core.mail import send_mail

logging.getLogger(__name__)
DEFAULT_FROM_EMAIL = settings.DEFAULT_FROM_EMAIL
BASE_URL = "http://127.0.0.1:8000/"
class Register(GenericAPIView):

    serializer_class = RegisterSerializer

    def post(self, request):
        """
        To register user in the system
        ---
        parameters:
                - name: email
                    description: Email of the user
                    required: true
                    type: string
                    paramType: form
                - name: name
                    description: Name of the user
                    required: true
                    type: string
                    paramType: form
                - name: password
                    description: Password
                    required: true
                    type: password
                    paramType: form
                - name: phone_number
                    description: Phone number of the user
                    required: true
                    type: string
                    paramType: form
                - name: country_code
                    description: Country Code of the user
                    required: true
                    type: string
                    paramType: form

        responseMessages:
                - code: 400
                    message: Invalid form details
                - code: 500
                    message: Internal server error
                - code: 200
                    message: Success
        response:
                - {
                      "message": "message string"
                  }
        """
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                data = serializer.data
                data['user_type'] = 'CONSUMER'
                front_image = request.FILES['profile_pic']
                current_time_stamp = int(round(time.time() * 1000))
                extension = front_image.name.split('.')[-1]
                front_image_file_name = str(data['name']) + str(current_time_stamp) + '.' + str(extension)
                asset_image = Image.open(front_image)
                front_image_file_name = os.path.join(BASE_DIR+'/media/', str(front_image_file_name))
            
                asset_image.save(front_image_file_name)
                data['profile_pic'] = front_image_file_name
                uid = uuid.uuid4()
                data['access_token'] = uid.hex
                # import hashlib
                # data['access_token'] = hashlib.sha256(b"hello world").hexdigest()
                body = BASE_URL + "app/verifyregistration/"+ data['access_token']
                send_mail('Hello from yash',
                 'Hello there this is verification mail \n' + body,
                  DEFAULT_FROM_EMAIL,
                  [data['email']], # [data['email']],
                  fail_silently=True)

                
                #send_organisation_verify_email(data)
                db.user.insert(data)

                return Response({'message': 'A verification mail has been sent on your mail.'}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': INTERNAL_SERVER_ERROR}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class Login(GenericAPIView):

    serializer_class = LoginSerializer

    def post(self, request):
        """
        To login in the system
        ---
        parameters:

                - name: email
                    description: Email of the user
                    required: true
                    type: string
                    paramType: form
                - name: password
                    description: Password
                    required: true
                    type: password
                    paramType: form


        responseMessages:
                - code: 400
                    message: Invalid form details
                - code: 401
                    message: Not authenticated
                - code: 422
                    message: Unprocessable request
                - code: 500
                    message: Internal server error
                - code: 200
                    message: Success
        response:
                - {
                    "access_token": ""                    
                  }
        """
        try:
            serializer = self.serializer_class(data=request.data)

            if serializer.is_valid():
                email = serializer.data['email']
                password = serializer.data['password']

                muser = db.user.find({'email': email})
                if muser.count() == 0:
                    return Response({'message': "This email is not registered."}, status=status.HTTP_200_OK)

                user = db.user.find({'email': email, 'password': password})
                

                if user.count() == 0:
                    muser = muser[0]
                    if muser['is_blocked']:
                        return Response({'message': "Your account is blocked. Admin or manger can reactivate your account."}, status=status.HTTP_200_OK)

                    number_of_attempts = muser['failed_login'] + 1

                    if number_of_attempts > 3:
                        db.user.update({'_id': muser['_id']}, {
                            '$set': {'is_blocked': True}})
                        return Response({'message': "Your account is blocked. Admin or manger can reactivate your account."}, status=status.HTTP_200_OK)

                    else:
                        db.user.update({'_id': muser['_id']}, {
                            '$set': {'failed_login': number_of_attempts}})

                    return Response({'message': "Invalid password. Number of attempts left : " + str(3-number_of_attempts)}, status=status.HTTP_200_OK)

                if user.count() > 0:

                    user = user[0]
                    if user['is_blocked']:
                        return Response({'message': "Your account is blocked. Admin or manger can reactivate your account."}, status=status.HTTP_200_OK)

                    db.user.update({'_id': user['_id']}, {
                        '$set': {'failed_login': 0}})

                    uid = uuid.uuid4()
                    access_token = uid.hex
                    db.user.update({'_id': user['_id']}, {
                        '$set': {'access_token': access_token}})

                    # Start User Activity Log
                    each = [{'event_timestamp': datetime.datetime.now(tz=pytz.utc).isoformat(),
                             'event': USER_LOGGED_IN, 'event_detail': USER_LOGGED_IN_MESSAGE % (user['name'])}]
                    db.activity_log.update({'user_id': ObjectId(user['_id'])},
                                           {'$push': {'activity': {'$each': each, '$sort': {'event_timestamp': -1}}}})
                    # End User Activity Log
                    return Response({'message': "User successfully logged in", 'access_token': access_token}, status=status.HTTP_200_OK)

                content = {'message': INVALID_DETAIL}
                return Response(content, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': INTERNAL_SERVER_ERROR}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class Logout(GenericAPIView):

    def get(self, request):
        try:
            user = get_user_from_token(request)
            if not user:
                return Response({'message': "Invalid access token"}, status=status.HTTP_401_UNAUTHORIZED)

            db.user.update({'_id': user['_id']}, {
                           '$set': {'access_token': ''}})

            return Response({'message': "User successfully logged out"}, status=status.HTTP_200_OK)

        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': "INTERNAL_SERVER_ERROR"}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class MyUsers(GenericAPIView):

    def get(self, request, **kwargs):
        try:
            # checking authentication
            if 'u_id' in kwargs:
                pass
            else:
                kwargs['u_id'] = ''

            user = get_user_from_token(request)
            if not user:
                return Response({'message': "Invalid access token. You are not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
            # end authentication

            data = []
            if user['user_type'] == 'CONSUMER':
                data = db.user.find({'_id': user['_id']})

            if user['user_type'] == 'MANAGER':
                data = db.user.find({'user_type': 'CONSUMER'})

            if user['user_type'] == 'ADMIN':
                data = db.user.find()

            response_object = []

            if kwargs['u_id']:
                for d in data:
                    if kwargs['u_id'] == str(d['_id']):
                        response_dict = {}
                        response_dict['_id'] = str(d['_id'])
                        response_dict['name'] = d['name']
                        response_dict['email'] = d['email']
                        response_dict['country_code'] = d['country_code']
                        response_dict['phone_number'] = d['phone_number']
                        response_dict['is_blocked'] = d['is_blocked']
                        response_dict['user_type'] = d['user_type']

                        return Response({'data': response_dict}, status=status.HTTP_200_OK)

            for d in data:
                response_dict = {}
                response_dict['_id'] = str(d['_id'])
                response_dict['name'] = d['name']
                response_dict['email'] = d['email']
                response_dict['country_code'] = d['country_code']
                response_dict['phone_number'] = d['phone_number']
                response_dict['is_blocked'] = d['is_blocked']
                response_dict['user_type'] = d['user_type']

                response_object.append(response_dict)
            return Response({'data': response_object}, status=status.HTTP_200_OK)

        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': "INTERNAL_SERVER_ERROR"}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        """
        To register user in the system
        ---
        parameters:
                - name: email
                    description: Email of the user
                    required: true
                    type: string
                    paramType: form
                - name: name
                    description: Name of the user
                    required: true
                    type: string
                    paramType: form
                - name: password
                    description: Password
                    required: true
                    type: password
                    paramType: form
                - name: phone_number
                    description: Phone number of the user
                    required: true
                    type: string
                    paramType: form
                - name: country_code
                    description: Country Code of the user
                    required: true
                    type: string
                    paramType: form

        responseMessages:
                - code: 400
                    message: Invalid form details
                - code: 500
                    message: Internal server error
                - code: 200
                    message: Success
        response:
                - {
                      "message": "message string"
                  }
        """
        try:
            # authentication
            user = get_user_from_token(request)
            if not user:
                return Response({'message': "Invalid access token. You are not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
            # end authentication

            if user['user_type'] == 'CONSUMER':
                return Response({'message': "You are not allowed to create user."}, status=status.HTTP_403_FORBIDDEN)

            serializer = RegisterSerializer(data=request.data)
            if serializer.is_valid():
                data = serializer.data
                data['is_blocked'] = False
                if user['user_type'] == 'MANAGER':
                    data['user_type'] = 'CONSUMER'
                # uid = uuid.uuid4()
                # data['password'] = uid.hex
                # send_organisation_verify_email(data)
                db.user.insert(data)

                return Response({'message': 'User created.'}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': INTERNAL_SERVER_ERROR}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, **kwargs):
        try:
            # checking authentication
            user = get_user_from_token(request)
            if not user:
                return Response({'message': "Invalid access token. You are not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
            # end authentication

            data = []
            if user['user_type'] == 'CONSUMER':
                data = db.user.find({'_id': user['_id']})

            if user['user_type'] == 'MANAGER':
                data = db.user.find({'user_type': 'CONSUMER'})

            if user['user_type'] == 'ADMIN':
                data = db.user.find()

            for d in data:
                if kwargs['u_id'] == str(d['_id']):

                    response_dict = request.data

                    if 'name' in request.data:
                        db.user.update({'_id': d['_id']}, {
                            '$set': {'name': response_dict['name']}})

                    if 'email' in request.data:
                        db.user.update({'_id': d['_id']}, {
                            '$set': {'email': response_dict['email']}})

                    if 'country_code' in request.data:
                        db.user.update({'_id': d['_id']}, {
                            '$set': {'country_code': response_dict['country_code']}})

                    if 'phone_number' in request.data:
                        db.user.update({'_id': d['_id']}, {
                            '$set': {'phone_number': response_dict['phone_number']}})

                    if 'password' in request.data: #and str(d['_id']) == str(user['_id']):
                        db.user.update({'_id': d['_id']}, {
                            '$set': {'password': response_dict['password']}})

                    if 'user_type' in request.data and (user['user_type'] == 'ADMIN'):
                        db.user.update({'_id': d['_id']}, {
                            '$set': {'user_type': response_dict['user_type']}})


                    if 'is_blocked' in request.data and (user['user_type'] == 'ADMIN' or user['user_type'] == 'MANAGER'):
                        db.user.update({'_id': d['_id']}, {
                            '$set': {'is_blocked': response_dict['is_blocked'], 'failed_login': 0}})

                    return Response({'message': 'User details updated.'}, status=status.HTTP_200_OK)

            else:
                return Response({'message': 'Invalid user id.'}, status=status.HTTP_400_BAD_REQUEST)

        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': "INTERNAL_SERVER_ERROR"}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, **kwargs):
        try:
            # checking authentication
            user = get_user_from_token(request)
            if not user:
                return Response({'message': "Invalid access token. You are not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
            # end authentication

            data = []
            if user['user_type'] == 'CONSUMER':
                data = db.user.find({'_id': user['_id']})

            if user['user_type'] == 'MANAGER':
                data = db.user.find({'user_type': 'CONSUMER'})

            if user['user_type'] == 'ADMIN':
                data = db.user.find()

            for d in data:
                if str(d['_id']) == kwargs['u_id']:
                    response_dict = {}
                    response_dict['_id'] = str(d['_id'])
                    response_dict['name'] = d['name']
                    response_dict['email'] = d['email']
                    response_dict['country_code'] = d['country_code']
                    response_dict['phone_number'] = d['phone_number']
                    response_dict['is_blocked'] = d['is_blocked']
                    response_dict['user_type'] = d['user_type']

                    db.user.remove({'_id': d['_id']})
                    return Response(response_dict, status=status.HTTP_200_OK)

            else:
                return Response({'message': 'Deletion unsuccessful.'}, status=status.HTTP_204_NO_CONTENT)

        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': "INTERNAL_SERVER_ERROR"}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class Myprofile(GenericAPIView):

    def get(self, request, **kwargs):
        try:
            # checking authentication
            user = get_user_from_token(request)
            if not user:
                return Response({'message': "Invalid access token. You are not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
            # end authentication

            response_object = []
            data = [user]
            for d in data:
                response_dict = {}
                response_dict['_id'] = str(d['_id'])
                response_dict['name'] = d['name']
                response_dict['email'] = d['email']
                response_dict['password'] = d['password']
                response_dict['country_code'] = d['country_code']
                response_dict['phone_number'] = d['phone_number']
                response_dict['is_blocked'] = d['is_blocked']
                response_dict['user_type'] = d['user_type']
                response_dict['profile_pic'] = d['profile_pic']

                response_object.append(response_dict)
                break
            return Response({'data': response_dict}, status=status.HTTP_200_OK)

        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': "INTERNAL_SERVER_ERROR"}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def put(self, request, **kwargs):
        try:
            # checking authentication
            user = get_user_from_token(request)
            if not user:
                return Response({'message': "Invalid access token. You are not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
            # end authentication

            data = [user]

            for d in data:           

                response_dict = request.data

                if 'name' in request.data:
                    db.user.update({'_id': d['_id']}, {
                        '$set': {'name': response_dict['name']}})

                if 'email' in request.data:
                    db.user.update({'_id': d['_id']}, {
                        '$set': {'email': response_dict['email']}})

                if 'country_code' in request.data:
                    db.user.update({'_id': d['_id']}, {
                        '$set': {'country_code': response_dict['country_code']}})

                if 'phone_number' in request.data:
                    db.user.update({'_id': d['_id']}, {
                        '$set': {'phone_number': response_dict['phone_number']}})

                if 'profile_pic' in request.FILES:
                    front_image = request.FILES['profile_pic']
                    current_time_stamp = int(round(time.time() * 1000))
                    extension = front_image.name.split('.')[-1]
                    front_image_file_name = str(d['name']) + str(current_time_stamp) + '.' + str(extension)
                    asset_image = Image.open(front_image)
                    front_image_file_name = os.path.join(BASE_DIR+'/media/', str(front_image_file_name))
                    asset_image.save(front_image_file_name)
                    

                    db.user.update({'_id': d['_id']}, {
                        '$set': {'profile_pic': front_image_file_name}})

                if 'password' in request.data and str(d['_id']) == str(user['_id']):
                    db.user.update({'_id': d['_id']}, {
                        '$set': {'password': response_dict['password']}})

                if 'user_type' in request.data and (user['user_type'] == 'ADMIN' or user['user_type'] == 'MANAGER'):
                    db.user.update({'_id': d['_id']}, {
                        '$set': {'user_type': response_dict['user_type']}})

                if 'is_blocked' in request.data and (user['user_type'] == 'ADMIN' or user['user_type'] == 'MANAGER'):
                    db.user.update({'_id': d['_id']}, {
                        '$set': {'is_blocked': response_dict['is_blocked'], 'failed_login': 0}})

                return Response({'message': 'User details updated.'}, status=status.HTTP_200_OK)


        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': "INTERNAL SERVER ERROR"}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, **kwargs):
        try:
            # checking authentication
            user = get_user_from_token(request)
            if not user:
                return Response({'message': "Invalid access token. You are not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
            # end authentication

            db.user.remove({'_id': user['_id']})
            return Response({'message':'Your account successfully deleted.'}, status=status.HTTP_200_OK)


        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': "INTERNAL_SERVER_ERROR"}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class VerifyRegistration(GenericAPIView):

    def get(self, request, **kwargs):
        try:
            user = db.user.find_one({'access_token': kwargs['access_token']})
            
            if not user:
                return Response({'message': "Invalid access token"}, status=status.HTTP_401_UNAUTHORIZED)

            db.user.update({'_id': user['_id']}, {
                           '$set': {'is_blocked': False}})

            return Response({'message': "User account successfully verified. You can now use login API."}, status=status.HTTP_200_OK)

        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': "INTERNAL_SERVER_ERROR"}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SendInvite(GenericAPIView):

    def post(self, request):
        try:
            user = get_user_from_token(request)
            if not user:
                return Response({'message': "Invalid access token"}, status=status.HTTP_401_UNAUTHORIZED)

            if user['user_type'] != 'ADMIN':
                return Response({'message': "You are not allowed to use this API. Only Admin can use this API."}, status=status.HTTP_403_FORBIDDEN)

            if 'email' not in request.data:
                return Response({'message': "Please enter a to email."}, status=status.HTTP_400_BAD_REQUEST)


            body = BASE_URL + "app/register/"
            send_mail('Hello from Datafonix',
            'Hello there, this is an invitation to join Datafonix by visting the below url in your browser \n' + body,
                DEFAULT_FROM_EMAIL, [request.data['email']],
                fail_silently=True)

            return Response({'message': "Invitation successfully sent to the user email."}, status=status.HTTP_200_OK)

        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': "INTERNAL_SERVER_ERROR"}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class ForgotPasswordView(GenericAPIView):

    def post(self, request):
        try:
            serializer = ForgotPasswordSerializer(data=request.data)
            if serializer.is_valid():
                data = serializer.data
                email = data['email']
                user = db.user.find_one({'email':email})
                print(user)
                if user:
                    send_mail('Greetings from Datafonix',
                    'Hello there, your account credentials are, Email: '+ user['email'] + ' and Password: ' + user['password'],
                        DEFAULT_FROM_EMAIL, [user['email']],
                        fail_silently=True)

                    return Response({'message': "Password successfully sent to the user email."}, status=status.HTTP_200_OK)
                else:
                    return Response({'message': "This email is not registered. Incorrect email."}, status=status.HTTP_200_OK)
             
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': "INTERNAL_SERVER_ERROR"}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class CalorieEntryView(GenericAPIView):

    def get(self, request, **kwargs):
        try:
            # checking authentication
            user = get_user_from_token(request)
            if not user:
                return Response({'message': "Invalid access token. You are not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
            # end authentication

            if user['user_type'] == 'MANAGER':
                return Response({'message': "Managers are not allowed to see Entries."}, status=status.HTTP_403_FORBIDDEN)

            response_object = []
            data = db.calorie.find()

            if user['user_type'] == 'CONSUMER':
                data = db.calorie.find({'user_id':user['_id']})
            
            if user['user_type'] == 'ADMIN':
                data = db.calorie.find()

            for d in data:
                response_dict = {}
                response_dict['_id'] = str(d['_id'])
                response_dict['user_id'] = d['user_id']
                response_dict['date'] = d['date']
                response_dict['time'] = d['time']
                response_dict['text'] = d['text']
                response_dict['number_of_calories'] = d['number_of_calories']
                response_dict['expected_number_of_calories'] = d['expected_number_of_calories']
                response_dict['flag'] = d['flag']
            
                response_object.append(response_dict)
                
            return Response({'data': response_dict}, status=status.HTTP_200_OK)

        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': "INTERNAL_SERVER_ERROR"}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            # authentication
            user = get_user_from_token(request)
            if not user:
                return Response({'message': "Invalid access token. You are not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
            # end authentication

            if user['user_type'] == 'MANAGER' or user['user_type'] == 'ADMIN':
                return Response({'message': "Managers and Admins are not allowed to add Entry."}, status=status.HTTP_403_FORBIDDEN)


            request.data['user_id'] = user['_id']

            serializer = CalorieEntrySerializer(data=request.data)
            if serializer.is_valid():
                data = serializer.data
                
                db.calorie.insert(data)

                return Response({'message': 'Calorie entry created.'}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': INTERNAL_SERVER_ERROR}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def put(self, request, **kwargs):
        try:
            # checking authentication
            user = get_user_from_token(request)
            if not user:
                return Response({'message': "Invalid access token. You are not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
            # end authentication

            if user['user_type'] == 'MANAGER':
                return Response({'message': "Managers are not allowed to update Entries."}, status=status.HTTP_403_FORBIDDEN)

            
            data = db.calorie.find({'_id':kwargs['id']})

            for d in data:           
                response_dict = request.data
                if 'calories' in request.data:
                    db.calorie.update({'_id':kwargs['id']}, {
                        '$set': {'calories': response_dict['calories']}})

                return Response({'message': 'Calorie details updated.'}, status=status.HTTP_200_OK)


        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': "INTERNAL SERVER ERROR"}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, **kwargs):
        try:
            # checking authentication
            user = get_user_from_token(request)
            if not user:
                return Response({'message': "Invalid access token. You are not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
            # end authentication

            if user['user_type'] == 'MANAGER':
                return Response({'message': "Managers are not allowed to delete Entries."}, status=status.HTTP_403_FORBIDDEN)


            db.calorie.remove({'_id': kwargs['id']})
            return Response({'message':'Calorie Entry successfully deleted.'}, status=status.HTTP_200_OK)


        except (AttributeError, KeyError, TypeError) as error:
            logging.error(error, exc_info=True)
            content = {'message': "INTERNAL_SERVER_ERROR"}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



        
    