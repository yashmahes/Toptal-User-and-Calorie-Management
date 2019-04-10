import re
from datetime import date
from common.messages import PASSWORD_VALIDATE, EMAIL_EXIST_MESSAGE, INVALID_ASSET_TYPE, EMAIL_NOT_EXIST_MESSAGE
from django.forms.utils import ValidationError
from mysite.settings import db


def validate_password(password):
    if len(password) < 7:
        raise ValidationError(PASSWORD_VALIDATE)


def validate_email(email):
    user = db.user.find({'email': email.lower()})
    if user.count() > 0:
        raise ValidationError(EMAIL_EXIST_MESSAGE)


def validate_asset_type(asset_type):
    asset_type = db.asset_type.find({'type': asset_type})
    if asset_type.count() != 1:
        raise ValidationError(INVALID_ASSET_TYPE)


def validate_forgot_password_email(email):
    user = db.user.find({'email': email})
    if user.count() == 0:
        raise ValidationError(EMAIL_NOT_EXIST_MESSAGE)


def is_alphabate(value):
    if re.match('^[a-zA-Z ]*$', value):
        return True
    else:
        raise ValidationError("Please insert alphabets only")


def check_dob(value):
    born = value
    today = date.today()
    if born >= today:
        raise ValidationError(
            "Ensure that birth date should be less than today's date")
    else:
        return True


def check_issue_date(value):
    issue_date = value
    today = date.today()
    if issue_date > today:
        raise ValidationError(
            "Ensure that issue date should be less than today's date")
    else:
        return True


def validate_phone_number(phone_number):
    if len(phone_number) > 10 or len(phone_number) < 8:
        raise ValidationError(
            'Make sure that phone number consist of either 8 or 10 digits')
