from fastapi import APIRouter, Depends, HTTPException
from bson.objectid import ObjectId
from starlette import status

from app.serializers.userSerializers import user_response_entity
from app.database import User
from .. import schemas, oauth2
from ..oauth2 import decode_role
from typing import List

router = APIRouter()


@router.get('/me', response_model=schemas.UserResponse)
def get_me(user_id: str = Depends(oauth2.require_user)):
    user = User.find_one({'_id': ObjectId(str(user_id))})
    encoded_role = user.get('role')
    if encoded_role:
        decoded_role = decode_role(encoded_role)
        user['role'] = decoded_role
    user_response = user_response_entity(user)
    return {"status": "success", "user": user_response}


@router.delete('/delete-users', status_code=status.HTTP_200_OK)
def delete_all_users(admin_user: str = Depends(oauth2.require_admin_user)):
    result = User.delete_many({})
    return {"status": "success", "deleted_count": result.deleted_count}


@router.get("/users-list")
def get_all_users(user_id: str = Depends(oauth2.require_admin_user)):
    users = User.find({})
    user_list = [user_response_entity(user) for user in users]
    return user_list


@router.get("/users-list/{user_id}")
def get_user_details(user_id: str, current_user: str = Depends(oauth2.require_admin_user)):
    user = User.find_one({"_id": ObjectId(user_id)})
    encoded_role = user.get('role')
    if encoded_role:
        decoded_role = decode_role(encoded_role)
        user['role'] = decoded_role
    user_response = user_response_entity(user)
    return user_response
