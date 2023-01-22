from typing import Generic, Optional, TypeVar
import strawberry

# INPUTS
@strawberry.input
class UserCreateInput:
    email: str
    name: Optional[str] = None
    password: str
    active: bool


@strawberry.input
class UserUpdateInput:
    email: str
    name: Optional[str] = None
    active: bool


T = TypeVar("T")


@strawberry.input
class Filter(Generic[T]):
    contains: Optional[T] = None


@strawberry.input
class WhereFilter:
    email: Optional[Filter[str]] = None


@strawberry.input
class PerfilCreateInput:
    name: str = None
    active: bool = True


@strawberry.input
class UsersQueryInput:
    search_string: Optional[str] = None
    active: Optional[bool] = None


# END INPUTS
