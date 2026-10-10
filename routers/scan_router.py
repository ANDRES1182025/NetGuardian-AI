from fastapi import APIRouter, Depends, HTTPException, status, Header, Response
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import List, Optional
from jose import jwt, JWTError

from database.connection import get_db
from models.scan_model import Scan
from models.user_model import UserModel
from schemas.scan_schema import ScanRequest, ScanResponse, AIScanExecutionResult, DashboardStats
from services.scan_service import execute_ai_scan, get_scans, get_dashboard_stats
from services.auth_service import SECRET_KEY, ALGORITHM
from services.pdf_service import generate_scan_pdf

router = APIRouter(
    prefix="/scans",
    tags=["Scans & Analytics"]
)

def get_current_user_optional(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)) -> Optional[UserModel]:
    """Obtiene el usuario actual si el token JWT es válido, o None si es Invitado."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if user_id:
            return db.query(UserModel).filter(UserModel.id == user_id).first()
    except JWTError:
        return None
    return None

@router.post("/run", response_model=AIScanExecutionResult)
def run_ai_analysis(
    payload: ScanRequest,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """Ejecuta el análisis aplicando las restricciones de rol (Invitado vs Analista/Admin)."""
    user_role = current_user.role if current_user else "guest"

    # Restricciones para el rol Invitado (Guest)
    if user_role == "guest":
        inspection_type_clean = payload.inspection_type.lower()
        if "profund" in inspection_type_clean or "deep" in inspection_type_clean:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="La Inspección Profunda de Vulnerabilidades (IA) requiere inicio de sesión como Analista o Administrador."
            )
        
        if payload.severity and payload.severity.capitalize() == "Alto":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="El nivel de Severidad 'Alto' está reservado para Analistas registrados."
            )

    try:
        assigned_user_id = current_user.id if current_user else (payload.user_id or 1)
        result = execute_ai_scan(
            db=db,
            target=payload.target,
            inspection_type=payload.inspection_type,
            severity_hint=payload.severity,
            user_id=assigned_user_id
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error en el motor de análisis: {str(e)}"
        )

@router.get("/", response_model=List[ScanResponse])
def list_scans(severity: Optional[str] = None, db: Session = Depends(get_db)):
    if severity and severity.capitalize() not in ["Bajo", "Medio", "Alto"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filtro de severidad no válido. Use 'Bajo', 'Medio' o 'Alto'."
        )
    return get_scans(db=db, severity=severity)

@router.get("/dashboard/stats", response_model=DashboardStats)
def scan_statistics(db: Session = Depends(get_db)):
    return get_dashboard_stats(db=db)

@router.delete("/clear/all", status_code=status.HTTP_200_OK)
def clear_all_scans(
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """Limpia masivamente el historial de escaneos y reinicia los contadores/IDs a 1."""
    if not current_user or current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operación no permitida. Solo el Administrador puede vaciar el historial global."
        )

    deleted_count = db.query(Scan).delete()
    
    # Reiniciar la secuencia de auto-incremento de IDs 
    try:
        table_name = Scan.__tablename__
        db.execute(text(f"TRUNCATE TABLE {table_name} RESTART IDENTITY CASCADE;"))
    except Exception:
        db.rollback()
        # Respaldo SQLite / DBs secundarias
        db.query(Scan).delete()
        try:
            db.execute(text("DELETE FROM sqlite_sequence WHERE name='scans';"))
        except Exception:
            pass

    db.commit()
    return {"message": f"Historial vaciado y contador reiniciado. Se eliminaron {deleted_count} registros."}

@router.get("/{scan_id}/pdf")
def download_scan_pdf(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="El registro de escaneo solicitado no existe."
        )

    user_info = {
        "username": current_user.username if current_user else "Usuario Invitado",
        "email": current_user.email if current_user else "invitado@netguardian.ai"
    }

    # Leer directamente de la BD el tipo de inspección persistido
    stored_type = getattr(scan, 'inspection_type', None) or "Análisis Rápido de Red"

    scan_dict = {
        "id": scan.id,
        "target": scan.target,
        "inspection_type": stored_type,
        "severity": scan.severity or "Bajo",
        "vulnerability_found": scan.vulnerability_found or "Sin amenazas críticas detectadas",
        "active_telemetry": scan.active_telemetry
    }

    pdf_bytes = generate_scan_pdf(scan_dict, user_info)

    filename = f"NetGuardian_Report_Scan_{scan_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )

@router.delete("/{scan_id}", status_code=status.HTTP_200_OK)
def delete_single_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """Elimina un registro de escaneo individual por ID (Requiere inicio de sesión)."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Debe iniciar sesión para eliminar registros."
        )

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="El registro de escaneo no existe."
        )
    db.delete(scan)
    db.commit()
    return {"message": f"Escaneo con ID {scan_id} eliminado correctamente."}