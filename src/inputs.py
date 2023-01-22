from typing import Optional
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


@strawberry.input
class PerfilCreateInput:
    name: str = None
    active: bool = True


# END INPUTS
