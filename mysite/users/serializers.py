from rest_framework import serializers
from common.messages import REQUIRED, EMAIL_VALID
from common.validations import validate_password, validate_email, validate_forgot_password_email, validate_phone_number
from django.contrib.auth.hashers import make_password


class RegisterSerializer(serializers.Serializer):
    name = serializers.CharField(
        max_length=50, error_messages={'blank': REQUIRED})
    email = serializers.EmailField(max_length=30, error_messages={'blank': REQUIRED, 'invalid': EMAIL_VALID},
                                   validators=[validate_email])
    password = serializers.CharField(max_length=12, error_messages={
                                     'blank': REQUIRED}, validators=[validate_password])
    country_code = serializers.CharField(
        max_length=6, min_length=1, error_messages={'blank': REQUIRED})
    phone_number = serializers.CharField(
        error_messages={'blank': REQUIRED}, validators=[validate_phone_number])

    is_blocked = serializers.BooleanField(default=True)

    access_token = serializers.CharField(max_length=255, default="")
    # manager_id = serializers.CharField(max_length=255, default="")

    failed_login = serializers.IntegerField(default=0)
    # profile_pic = serializers.ImageField(
    #     use_url=True, allow_null=True, required=False)

    def validate(self, attrs):

        attrs['email'] = attrs['email'].lower()
        return attrs


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(
        error_messages={'blank': REQUIRED, 'invalid': EMAIL_VALID})
    password = serializers.CharField(max_length=12, error_messages={
        'blank': REQUIRED}, validators=[validate_password])

    def validate(self, attrs):
        attrs['email'] = attrs['email'].lower()
        return attrs


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(error_messages={
        'blank': REQUIRED, 'invalid': EMAIL_VALID}, validators=[validate_forgot_password_email])


class CalorieEntrySerializer(serializers.Serializer):
    #user_id = serializers.CharField(max_length=255, default="")
    date = serializers.CharField(max_length=255, default="")
    time = serializers.CharField(max_length=255, default="")
    text = serializers.CharField(max_length=255, default="")
    number_of_calories = serializers.IntegerField(default=0)
    expected_number_of_calories = serializers.IntegerField(default=0)
    flag = serializers.BooleanField(default=False)
