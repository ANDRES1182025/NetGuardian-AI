from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from database.connection import get_db
from schemas.user_schema import UserCreate, UserResponse, UserRoleUpdate
from services.user_service import create_user
from services.auth_service import get_current_user
from models.user_model import UserModel

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)

def verify_admin_role(current_user: UserModel = Depends(get_current_user)) -> UserModel:
    """Verifica que el usuario autenticado por JWT tenga rol de Administrador."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso restringido únicamente a Administradores del sistema."
        )
    return current_user

@router.post("/", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    try:
        return create_user(db=db, user=user)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al registrar usuario: {str(e)}")

@router.get("/", response_model=List[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    admin_user: UserModel = Depends(verify_admin_role)
):
    """Permite listar todos los usuarios registrados (Exclusivo para Administradores)."""
    return db.query(UserModel).all()

@router.put("/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: int,
    role_data: UserRoleUpdate,
    db: Session = Depends(get_db),
    admin_user: UserModel = Depends(verify_admin_role)
):
    """Permite modificar el rol de un usuario (Exclusivo para Administradores)."""
    target_user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    target_user.role = role_data.role
    db.commit()
    db.refresh(target_user)
    return target_user