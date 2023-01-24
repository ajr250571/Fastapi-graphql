from prisma import Prisma

prisma = Prisma()


await prisma.connect()
prisma.perfil.create(
    data={
        "name": "Admin",
        "active": True,
    },
)
prisma.disconnect()
