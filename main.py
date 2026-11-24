from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database.connection import engine, Base
from routers import user_router, scan_router, auth_router

# Crear las tablas en la base de datos automáticamente
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="NetGuardian AI - SOC API",
    version="2.0.0",
    description="Backend oficial de NetGuardian AI para análisis de vulnerabilidades mediante IA y gestión de operaciones SOC.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Registrar los Routers del sistema
app.include_router(auth_router.router)
app.include_router(user_router.router)
app.include_router(scan_router.router)


@app.get("/")
def read_root():
    return {
        "message": "¡Bienvenido al backend de NetGuardian AI!",
        "status": "activo",
        "database": "Conectada y sincronizada con PostgreSQL",
    }
