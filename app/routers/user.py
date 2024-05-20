from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, HTTPException
from bson.objectid import ObjectId
from starlette import status

from app.serializers.userSerializers import user_response_entity
from app.database import User
from .. import schemas, oauth2
from ..config import FERNET_KEY

router = APIRouter()


def decode_role(encoded_role: str) -> str:
    cipher_suite = FERNET_KEY
    try:
        decoded_role = cipher_suite.decrypt(encoded_role).decode()
        return decoded_role
    except InvalidToken:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role token"
        )


@router.get('/me', response_model=schemas.UserResponse)
def get_me(user_id: str = Depends(oauth2.require_user)):
    user = User.find_one({'_id': ObjectId(str(user_id))})
    encoded_role = user.get('role')
    if encoded_role:
        decoded_role = decode_role(encoded_role)
        user['role'] = decoded_role
    user_response = user_response_entity(user)
    return {"status": "success", "user": user_response}
