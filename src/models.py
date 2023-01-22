from typing import Generic, List, Optional, TypeVar
import strawberry
from src.prisma import prisma


# MODELS
@strawberry.type
class Perfil:
    id: Optional[strawberry.ID] = None
    name: str
    active: bool

    @strawberry.field
    async def users(self) -> List["User"]:
        users = await prisma.user.find_many(where={"perfilId": self.id})
        return users


@strawberry.type
class User:
    id: Optional[strawberry.ID] = None
    email: str
    name: Optional[str] = None
    active: bool
    perfilId: str

    @strawberry.field
    async def perfil(self) -> "Perfil":
        return await prisma.perfil.find_unique(where={"id": self.perfilId})


@strawberry.type
class AuthPayload:
    token: str
    user: User


# END mODELS
