import re
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from fastapi import APIRouter, Response, status, Depends, HTTPException
from app.database import User
from app.serializers.userSerializers import user_entity, user_response_entity
from .. import schemas, utils
from app.oauth2 import AuthJWT
from ..config import settings, FERNET_KEY

router = APIRouter()

ACCESS_TOKEN_EXPIRES_IN = settings.ACCESS_TOKEN_EXPIRES_IN
REFRESH_TOKEN_EXPIRES_IN = settings.REFRESH_TOKEN_EXPIRES_IN


@router.post('/register', status_code=status.HTTP_201_CREATED, response_model=schemas.UserResponse)
async def create_user(payload: schemas.CreateUserSchema):
    # Check if user already exists
    user = User.find_one({"email": payload.email.lower()})
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account already exists")

    # Verify password
    validate_password(payload.password, payload.email, payload.name)

    # Compare password and passwordConfirm
    if payload.password != payload.passwordConfirm:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match")

    # Hash the password
    payload.password = utils.hash_password(payload.password)
    del payload.passwordConfirm

    cipher_suite = FERNET_KEY
    payload.role = payload.role.lower()
    payload.role = cipher_suite.encrypt(payload.role.encode())
    payload.verified = True
    payload.email = payload.email.lower()
    payload.created_at = datetime.utcnow()
    payload.updated_at = payload.created_at

    result = User.insert_one(payload.dict())
    new_user = user_response_entity(User.find_one({"_id": result.inserted_id}))
    return {"status": "success", "user": new_user}


@router.post("/login")
def login(payload: schemas.LoginUserSchema, response: Response, authorize: AuthJWT = Depends()):
    # Check if the user exists
    db_user = User.find_one({"email": payload.email.lower()})
    if not db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect Email or Password")

    user = user_entity(db_user)

    # Check if the password is valid
    if not utils.verify_password(payload.password, user["password"]):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Incorrect Email or Password')

    # Create access token
    access_token = authorize.create_access_token(
        subject=str(user["id"]), expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN)
    )

    # Create refresh token
    refresh_token = authorize.create_refresh_token(
        subject=str(user["id"]), expires_time=timedelta(minutes=REFRESH_TOKEN_EXPIRES_IN)
    )

    # Store refresh and access tokens in cookie
    response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60, ACCESS_TOKEN_EXPIRES_IN * 60, '/',
                        None, False, True, 'lax')
    response.set_cookie('refresh_token', refresh_token, REFRESH_TOKEN_EXPIRES_IN * 60, REFRESH_TOKEN_EXPIRES_IN * 60,
                        '/', None, False, True, 'lax')
    response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60, ACCESS_TOKEN_EXPIRES_IN * 60, '/', None,
                        False, False, 'lax')

    return {'status': 'success', 'user_access_token': access_token, 'user_refresh_token': refresh_token}


@router.get('/refresh')
def refresh_token(response: Response, authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_refresh_token_required()
        user_id = authorize.get_jwt_subject()

        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not refresh access token')

        user = user_entity(User.find_one({'_id': ObjectId(str(user_id))}))

        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='The user belonging to this token no longer exists')

        access_token = authorize.create_access_token(
            subject=str(user["id"]), expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN)
        )

    except Exception as e:
        error = e.__class__.__name__
        if error == 'MissingTokenError':
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Please provide refresh token')
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60, ACCESS_TOKEN_EXPIRES_IN * 60, '/',
                        None, False, True, 'lax')
    response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60, ACCESS_TOKEN_EXPIRES_IN * 60, '/', None,
                        False, False, 'lax')
    return {'access_token': access_token}


@router.get('/logout', status_code=status.HTTP_200_OK)
def logout(response: Response, authorize: AuthJWT = Depends()):
    authorize.unset_jwt_cookies()
    response.set_cookie('logged_in', '', -1)
    return {'status': 'success'}


# Compile regular expressions outside the function for better performance
number_regex = re.compile(r'[0-9]')
capital_letter_regex = re.compile(r'[A-Z]')
special_symbol_regex = re.compile(r'(?=.*?[^A-Za-z\s0-9])')


def validate_password(password, mail, name):
    if len(password) < 12:
        raise HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE, detail="Minimum password length is 12 symbols")
    if number_regex.search(password) is None:
        raise HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE,
                            detail="Password must contain numbers (at least one)")
    if capital_letter_regex.search(password) is None:
        raise HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE,
                            detail="Password must contain capital letters (at least one)")
    if special_symbol_regex.search(password) is None:
        raise HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE,
                            detail="Password must contain special symbols (at least one)")
    if re.search(name, password, re.IGNORECASE) is not None:
        raise HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE, detail="Password can't contain name")
    if re.search(mail.split("@")[0], password, re.IGNORECASE) is not None:
        raise HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE, detail="Password can't contain email")
