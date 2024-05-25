import base64
from typing import List

from cryptography.fernet import InvalidToken
from fastapi import Depends, HTTPException, status
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel
from bson.objectid import ObjectId
from app.serializers.userSerializers import user_entity
from .database import User
from .config import settings, FERNET_KEY


class Settings(BaseModel):
    authjwt_algorithm: str = settings.JWT_ALGORITHM
    authjwt_decode_algorithms: List[str] = [settings.JWT_ALGORITHM]
    authjwt_token_location: set = {'cookies', 'headers'}
    authjwt_access_cookie_key: str = 'access_token'
    authjwt_refresh_cookie_key: str = 'refresh_token'
    authjwt_secret_key: str = "secret_key"
    authjwt_cookie_csrf_protect: bool = False
    authjwt_public_key: str = base64.b64decode(settings.JWT_PUBLIC_KEY).decode('utf-8')
    authjwt_private_key: str = base64.b64decode(settings.JWT_PRIVATE_KEY).decode('utf-8')


@AuthJWT.load_config
def get_config():
    return Settings()


class NotVerified(Exception):
    pass


class UserNotFound(Exception):
    pass


def require_user(authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_required()
        user_id = authorize.get_jwt_subject()
        user = user_entity(User.find_one({'_id': ObjectId(str(user_id))}))

        if not user:
            raise UserNotFound('User no longer exist')

        if not user["verified"]:
            raise NotVerified('You are not verified')

    except Exception as e:
        error = e.__class__.__name__
        print(error)

        if error == 'MissingTokenError':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='You are not logged in'
            )

        if error == 'UserNotFound':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='User no longer exist'
            )

        if error == 'NotVerified':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Please verify your account'
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Token is invalid or has expired'
        )

    return user_id


def decode_role(encoded_role: str) -> str:
    try:
        cipher_suite = FERNET_KEY
        decoded_role = cipher_suite.decrypt(encoded_role).decode()
        return decoded_role
    except InvalidToken:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role token"
        )



def require_user(authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_required()
        user_id = authorize.get_jwt_subject()
        user = User.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user_id
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

def require_admin_user(authorize: AuthJWT = Depends()):
    user_id = require_user(authorize)
    user = User.find_one({"_id": ObjectId(user_id)})
    role = decode_role(user['role'])
    if role != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return user_id
