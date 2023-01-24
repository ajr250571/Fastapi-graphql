from logging import info
import typing
from fastapi import HTTPException, Request, WebSocket, status
import strawberry
from strawberry import BasePermission
from src.prisma import prisma
from typing import Dict, List, Optional
import bcrypt
from jose import jwt
from datetime import datetime, timedelta
from src.models import Perfil, User, AuthPayload
from src.inputs import (
    PerfilCreateInput,
    UserCreateInput,
    UserUpdateInput,
    UsersQueryInput,
)
import json


ALGORITHM = "HS256"
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24


# FUNCTIONS
def password_check(passwd):
    message = ""
    SpecialSym = ["$", "@", "#", "%"]
    val = True

    if len(passwd) < 6:
        message = "length should be at least 6"
        val = False

    if len(passwd) > 20:
        message = "length should be not be greater than 8"
        val = False

    if not any(char.isdigit() for char in passwd):
        message = "Password should have at least one numeral"
        val = False

    if not any(char.isupper() for char in passwd):
        message = "Password should have at least one uppercase letter"
        val = False

    if not any(char.islower() for char in passwd):
        message = "Password should have at least one lowercase letter"
        val = False

    if not any(char in SpecialSym for char in passwd):
        message = "Password should have at least one of the symbols $@#"
        val = False
    if val:
        return val
    else:
        raise HTTPException(
            status.HTTP_411_LENGTH_REQUIRED,
            message,
        )


async def validatePassword(password: str, hash: str) -> bool:
    return await bcrypt.checkpw(password.encode(), hash)


async def search_user(email: str) -> User:

    user = await prisma.user.find_unique(where={"email": email})
    return user


async def auth_user(token: str) -> User:
    try:
        email: str = jwt.decode(token, SECRET_KEY, algorithms=[
                                ALGORITHM]).get("sub")
        user = await search_user(email)
    except:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Token no Autorizado")

    if not user.active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Usuario Inactivo")

    return user


async def decodeJWT(token: str) -> bool:
    try:
        await auth_user(token)
        return True
    except:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Token no Autorizado")

    return False


# END FUNCTIONES

# CLASS
class IsAuthenticated(BasePermission):
    message = "User is not authenticated"

    def has_permission(self, source: typing.Any, info: info, **kwargs) -> bool:
        request: typing.Union[Request, WebSocket] = info.context["request"]
        authorization = request.headers.get("Authorization")
        if "Authorization" in request.headers:
            auth = decodeJWT(authorization)
            return auth

        return False


@strawberry.type
class Error:
    message: str


# END CLASS

# QUERY
@strawberry.type
class Query:
    @strawberry.field(permission_classes=[IsAuthenticated])
    async def users(
        self, filter: Optional[UsersQueryInput] = strawberry.UNSET
    ) -> Optional[List[User]]:
        if filter != strawberry.UNSET:
            if (not filter.search_string is None) and (not filter.active is None):
                users = await prisma.user.find_many(
                    where={
                        "OR": [
                            {"email": {"contains": filter.search_string}},
                            {"name": {"contains": filter.search_string}},
                        ],
                        "AND": [
                            {"active": filter.active},
                        ],
                    }
                )
            if (not filter.search_string is None) and (filter.active is None):
                users = await prisma.user.find_many(
                    where={
                        "OR": [
                            {"email": {"contains": filter.search_string}},
                            {"name": {"contains": filter.search_string}},
                        ],
                    }
                )

            if (filter.search_string is None) and (not filter.active is None):
                if not filter.active is None:
                    users = await prisma.user.find_many(
                        where={
                            "AND": [
                                {"active": filter.active},
                            ],
                        }
                    )
        else:
            users = await prisma.user.find_many()

        return users

    @strawberry.field(permission_classes=[IsAuthenticated])
    async def users_by_email(self, email: str) -> Optional[List[User]]:
        users = await prisma.user.find_many(where={"email": {"contains": email}})
        return users

    @strawberry.field(permission_classes=[IsAuthenticated])
    async def user(self, id: strawberry.ID) -> Optional[User]:
        user = await prisma.user.find_unique(where={"id": id})
        return user

    @strawberry.field
    async def me(token: str) -> Optional[User]:
        try:
            user = await auth_user(token)
            return user
        except:
            raise

    @strawberry.field(permission_classes=[IsAuthenticated])
    async def perfil(self, id: strawberry.ID) -> Optional[Perfil]:
        return await prisma.perfil.find_unique(where={"id": id})

    @strawberry.field(permission_classes=[IsAuthenticated])
    async def perfiles(self) -> Optional[List[Perfil]]:
        perfiles = await prisma.perfil.find_many()
        return perfiles


# END QUERYS

# MUTATION
@strawberry.type
class Mutation:
    @strawberry.mutation()
    async def user_create(self, user: UserCreateInput) -> User:
        pwd = user.password

        if not password_check(pwd):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "Password invalido.")

        bytePwd = pwd.encode()
        byteHash = bcrypt.hashpw(bytePwd, bcrypt.gensalt())
        pwdHash = byteHash.decode()

        # ID de perfil 'Invitado'
        perfil = await prisma.perfil.find_unique(where={"name": "Invitado"})
        # print("perfilId", perfil.id)

        user = await prisma.user.create(
            data={
                "name": user.name,
                "email": user.email,
                "password": pwdHash,
                "active": user.active,
            },
        )

        await prisma.user.update(
            where={"id": user.id},
            data={
                "perfilId": perfil.id,
            },
        )
        return user

    @strawberry.mutation(permission_classes=[IsAuthenticated])
    async def user_update(id: str, user: UserUpdateInput) -> User:
        user = await prisma.user.update(
            where={
                "id": id,
            },
            data={
                "email": user.email,
                "name": user.name,
                "active": user.active,
              },
        )
        return user

    @strawberry.mutation(permission_classes=[IsAuthenticated])
    async def user_delete(id: str) -> User:
        user = await prisma.user.delete(
            where={
                "id": id,
            },
        )
        return user

    @strawberry.mutation
    async def login(self, email: str, password: str) -> AuthPayload:
        user = await prisma.user.find_unique(
            where={
                "email": email,
            }
        )
        validated = validatePassword(password, user.password)
        if validated:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = {"sub": user.email, "exp": expire}
            token = jwt.encode(access_token, SECRET_KEY, algorithm=ALGORITHM)
            return AuthPayload(token=token, user=user)

        return None

    @strawberry.mutation()
    async def perfil_create(self, perfil: PerfilCreateInput) -> Perfil:
        perfil = await prisma.perfil.create(
            data={
                "name": perfil.name,
                "active": perfil.active,
            },
        )
        return perfil


# END MUTATIONS
