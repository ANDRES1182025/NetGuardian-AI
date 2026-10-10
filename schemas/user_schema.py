from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional

ALLOWED_ROLES = ["admin", "analyst", "guest"]

# Esquema para el registro de nuevos usuarios
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: Optional[str] = "analyst"

    @field_validator('password')
    @classmethod
    def validate_password_length(cls, v: str) -> str:
        if len(v.encode('utf-8')) > 72:
            raise ValueError('La contraseña no puede superar los 72 bytes por limitaciones de seguridad de Bcrypt.')
        return v

    @field_validator('role')
    @classmethod
    def validate_role(cls, v: Optional[str]) -> str:
        if v and v.lower() not in ALLOWED_ROLES:
            raise ValueError(f"Rol no válido. Permisos permitidos: {', '.join(ALLOWED_ROLES)}")
        return v.lower() if v else "analyst"

# Esquema para la entrada del formulario de Inicio de Sesión
class UserLogin(BaseModel):
    email: EmailStr
    password: str

# Esquema para actualizar el rol de un usuario (para Administradores)
class UserRoleUpdate(BaseModel):
    role: str

    @field_validator('role')
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v.lower() not in ALLOWED_ROLES:
            raise ValueError(f"Rol no válido. Permisos permitidos: {', '.join(ALLOWED_ROLES)}")
        return v.lower()

# Esquema para la respuesta pública del Usuario 
class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str

    class Config:
        from_attributes = True

# Esquema para la respuesta del Token JWT al iniciar sesión correctamente
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str = "analyst"

# Esquema para la información interna decodificada desde el Token JWT
class TokenData(BaseModel):
    user_id: Optional[int] = None
    email: Optional[str] = None
    role: Optional[str] = None