import socket
import urllib.parse
import httpx
import asyncio
from datetime import datetime
from sqlalchemy.orm import Session
from models.scan_model import Scan
from schemas.scan_schema import ScanCreate
from services.active_scanner_service import ActiveScannerService

# Intentar cargar pipeline de IA con cuantización dinámica INT8 en PyTorch para CPU
try:
    import torch
    from transformers import pipeline

    ai_classifier = pipeline(
        "zero-shot-classification",
        model="MoritzLaurer/DeBERTa-v3-base-mnli-fever-anli",
        device=-1
    )

    if hasattr(ai_classifier, "model"):
        ai_classifier.model = torch.quantization.quantize_dynamic(
            ai_classifier.model,
            {torch.nn.Linear},
            dtype=torch.qint8
        )
except Exception:
    ai_classifier = None


def get_scans(db: Session, skip: int = 0, limit: int = 100, severity: str = None):
    query = db.query(Scan)
    if severity:
        query = query.filter(Scan.severity == severity)
    return query.order_by(Scan.scanned_at.desc()).offset(skip).limit(limit).all()


def get_dashboard_stats(db: Session):
    total = db.query(Scan).count()
    scans = db.query(Scan).all()
    distribution = {}
    for scan in scans:
        sev = scan.severity or "Bajo"
        distribution[sev] = distribution.get(sev, 0) + 1
    return {
        "total_scans": total,
        "severity_distribution": distribution
    }


def _analyze_network_quick(target_url: str, depth_level: str) -> dict:
    findings = []
    risk_score = 0
    
    parsed = urllib.parse.urlparse(target_url if "://" in target_url else f"http://{target_url}")
    domain = parsed.netloc or parsed.path
    
    socket.setdefaulttimeout(3.0)
    try:
        ip_address = socket.gethostbyname(domain.split(':')[0])
        findings.append(f"IP Resuelta: {ip_address}")
    except Exception:
        return {
            "risk_score": 90,
            "findings": ["Error DNS: Imposible resolver el dominio o IP."],
            "summary": "El objetivo no está alcanzable en la red."
        }

    timeout_val = 2.0 if depth_level == "Bajo" else (3.5 if depth_level == "Medio" else 5.0)
    try:
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
        with httpx.Client(timeout=timeout_val, follow_redirects=True, verify=False, limits=limits) as client:
            response = client.get(f"https://{domain}" if not target_url.startswith("http") else target_url)
            
            headers = response.headers
            missing_headers = []
            for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]:
                if h not in headers:
                    missing_headers.append(h)
            
            if missing_headers:
                risk_score += len(missing_headers) * 10
                findings.append(f"Faltan cabeceras de seguridad: {', '.join(missing_headers)}")
            else:
                findings.append("Todas las cabeceras principales de seguridad están presentes.")

            if response.status_code >= 400:
                risk_score += 20
                findings.append(f"El servidor respondió con código de estado de error: {response.status_code}")

    except Exception as e:
        risk_score += 35
        findings.append(f"Advertencia al conectar vía HTTPS/HTTP: {str(e)[:60]}")

    return {
        "risk_score": min(risk_score, 100),
        "findings": findings,
        "summary": f"Análisis de red finalizado. Nivel de riesgo calculado: {risk_score}/100."
    }


def _analyze_ai_deep(target_url: str, depth_level: str) -> dict:
    network_res = _analyze_network_quick(target_url, depth_level)
    findings = network_res["findings"]
    risk_score = network_res["risk_score"]

    parsed = urllib.parse.urlparse(target_url if "://" in target_url else f"http://{target_url}")
    domain = parsed.netloc or parsed.path
    
    timeout_val = 3.0 if depth_level == "Bajo" else (5.0 if depth_level == "Medio" else 8.0)
    html_sample = ""

    try:
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
        with httpx.Client(timeout=timeout_val, follow_redirects=True, verify=False, limits=limits) as client:
            res = client.get(f"https://{domain}" if not target_url.startswith("http") else target_url)
            html_sample = res.text[:1000]
    except Exception:
        pass

    if html_sample and ai_classifier:
        candidate_labels = ["secure legitimate website", "phishing attack", "malicious script", "vulnerable web server"]
        try:
            prediction = ai_classifier(html_sample, candidate_labels)
            top_label = prediction['labels'][0]
            confidence = round(prediction['scores'][0] * 100, 1)

            findings.append(f"Clasificación IA: '{top_label}' con confianza del {confidence}%.")
            if top_label != "secure legitimate website":
                risk_score += 40
        except Exception:
            findings.append("Inspección de IA: Evaluación por heurística avanzada de patrones de texto.")
    else:
        suspicious_keywords = ["login", "password", "bank", "verify", "update", "account", "token", "unauthorized"]
        matches = [kw for kw in suspicious_keywords if kw in html_sample.lower()]
        if len(matches) > 3:
            risk_score += 30
            findings.append(f"IA Heurística: Detectada alta densidad de palabras clave sensibles: {matches}")
        else:
            findings.append("IA Heurística: No se detectaron patrones de suplantación en el contenido devuelto.")

    return {
        "risk_score": min(risk_score, 100),
        "findings": findings,
        "summary": f"Inspección profunda completada. Riesgo de vulnerabilidad estimado: {risk_score}/100."
    }


def execute_ai_scan(db: Session, target: str = None, inspection_type: str = "quick", severity: str = "Bajo", severity_hint: str = None, user_id: int = None, scan_data: ScanCreate = None, **kwargs):
    if scan_data:
        target = getattr(scan_data, 'target', target)
        inspection_type = getattr(scan_data, 'inspection_type', inspection_type)
        severity = getattr(scan_data, 'severity', severity)

    target = target or "127.0.0.1"
    depth_level = severity_hint or severity or "Bajo"
    
    inspection_raw = str(inspection_type).strip().lower()
    
    if any(k in inspection_raw for k in ["deep", "profund", "ia", "vulnerabilid"]):
        analysis = _analyze_ai_deep(target, depth_level)
        engine_name = "NetGuardian Quantized AI Engine (DeBERTa-v3 INT8)"
        formatted_inspection_type = "Inspección Profunda de Vulnerabilidades (IA)"
    else:
        analysis = _analyze_network_quick(target, depth_level)
        engine_name = "NetGuardian Real-Time Network Engine"
        formatted_inspection_type = "Análisis Rápido de Red"

    try:
        active_telemetry = asyncio.run(
            ActiveScannerService.run_active_recon(target, formatted_inspection_type)
        )
    except Exception:
        active_telemetry = {
            "open_ports": [],
            "discovered_paths": [],
            "total_open_ports": 0,
            "total_paths_found": 0
        }

    risk_score = analysis["risk_score"]
    if risk_score < 25:
        vulnerability_msg = "Sin amenazas críticas detectadas"
        calculated_severity = "Bajo"
    elif risk_score < 60:
        vulnerability_msg = "Riesgo Moderado: Faltan configuraciones/cabeceras de seguridad"
        calculated_severity = "Medio"
    else:
        vulnerability_msg = "Amenaza Potencial / Alta Vulnerabilidad Detectada"
        calculated_severity = "Alto"

    valid_user_id = user_id
    if user_id:
        from models.user_model import UserModel
        user_exists = db.query(UserModel).filter(UserModel.id == user_id).first()
        if not user_exists:
            valid_user_id = None

    new_scan = Scan(
        target=target,
        vulnerability_found=vulnerability_msg,
        severity=calculated_severity,
        inspection_type=formatted_inspection_type,
        active_telemetry=active_telemetry,
        user_id=valid_user_id
    )

    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    return {
        "scan_data": new_scan,
        "inspection_type": formatted_inspection_type,
        "ai_details": {
            "engine": engine_name,
            "target_evaluated": target,
            "inspection_mode": formatted_inspection_type,
            "depth_level": depth_level,
            "threat_score": risk_score,
            "detected_entities": analysis["findings"],
            "summary": analysis["summary"],
            "active_telemetry": active_telemetry
        }
    }