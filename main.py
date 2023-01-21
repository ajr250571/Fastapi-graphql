from pydantic import BaseModel
import strawberry
from fastapi import FastAPI
from strawberry.fastapi import GraphQLRouter
from src.prisma import prisma
from src.resolvers import Query, Mutation

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
)

graphql_app = GraphQLRouter(schema)

app = FastAPI()


@app.on_event("startup")
async def startup():
    await prisma.connect()


@app.on_event("shutdown")
async def shutdown():
    await prisma.disconnect()


app.include_router(graphql_app, prefix="/graphql")
