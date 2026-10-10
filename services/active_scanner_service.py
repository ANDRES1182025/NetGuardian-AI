import asyncio
import socket
import urllib.parse
import httpx
from typing import List, Dict, Any



# Puertos para Análisis Rápido 
QUICK_PORTS = [80, 443, 21, 22, 25, 8080, 8443, 3306, 5432, 27017]

# Puertos ampliados para Inspección Profunda (IA)
DEEP_PORTS = QUICK_PORTS + [8000, 8081, 8888, 3000, 5000, 6379, 11211, 1433, 1521, 5900, 8008, 9000, 9200, 9300, 27018]

# Rutas ligeras para Análisis Rápido
QUICK_PATHS = [
    "/admin", "/login", "/robots.txt", "/.well-known/security.txt"
]

# Rutas ampliadas para Inspección Profunda (IA)
DEEP_PATHS = QUICK_PATHS + [
    "/api", "/v1", "/v2", "/swagger.json", "/api-docs",
    "/.env", "/config.json", "/backup.sql", "/.git/HEAD"
]

# Tiempos de espera 
PORT_SCAN_TIMEOUT = 0.8  # Segundos por puerto
HTTP_SCAN_TIMEOUT = 1.5  # Segundos por petición HTTP
MAX_CONCURRENT_TASKS = 20  # Control de concurrencia


class ActiveScannerService:
    """
    Servicio de Inteligencia Ofensiva y Escaneo Activo.
    Sondea puertos y verifica rutas mediante sockets e I/O asíncrono.
    """

    @staticmethod
    def _extract_hostname(target: str) -> str:
        """Extrae la IP o Dominio limpio desde una URL u Host."""
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        parsed = urllib.parse.urlparse(target)
        return parsed.hostname or target

    @classmethod
    async def scan_single_port(cls, host: str, port: int, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
        """Verifica la apertura de un puerto TCP específico."""
        async with semaphore:
            result = {"port": port, "state": "closed", "service": "unknown"}
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=PORT_SCAN_TIMEOUT)
                
                result["state"] = "open"
                
                try:
                    result["service"] = socket.getservbyport(port, "tcp")
                except OSError:
                    result["service"] = "custom-http" if port in [8000, 8081, 3000, 5000] else "unknown"

                writer.close()
                await writer.wait_closed()
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass
            return result

    @classmethod
    async def scan_ports(cls, target: str, is_deep: bool = False) -> List[Dict[str, Any]]:
        """Escanea la lista de puertos seleccionada según el modo."""
        hostname = cls._extract_hostname(target)
        ports_to_scan = DEEP_PORTS if is_deep else QUICK_PORTS
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)

        tasks = [cls.scan_single_port(hostname, port, semaphore) for port in ports_to_scan]
        results = await asyncio.gather(*tasks)
        
        # Devolver únicamente los puertos detectados como abiertos
        return [p for p in results if p["state"] == "open"]

    @classmethod
    async def discover_paths(cls, target: str, is_deep: bool = False) -> List[Dict[str, Any]]:
        """Sondea directorios y endpoints comunes."""
        if not target.startswith(("http://", "https://")):
            base_url = f"https://{target}"
        else:
            base_url = target.rstrip("/")

        paths_to_check = DEEP_PATHS if is_deep else QUICK_PATHS
        findings = []

        async with httpx.AsyncClient(timeout=HTTP_SCAN_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in paths_to_check:
                full_url = f"{base_url}{path}"
                try:
                    response = await client.get(full_url)
                    if response.status_code in [200, 301, 302, 401, 403]:
                        findings.append({
                            "path": path,
                            "status_code": response.status_code,
                            "risk_level": "Alto" if response.status_code == 200 and path in ["/.env", "/backup.sql"] else "Informativo"
                        })
                except (httpx.RequestError, httpx.HTTPError):
                    continue

        return findings

    @classmethod
    async def run_active_recon(cls, target: str, inspection_type: str) -> Dict[str, Any]:
        """Orquestador principal que ejecuta la recolección activa."""
        is_deep = any(k in str(inspection_type).lower() for k in ["deep", "profund", "ia"])
        
        open_ports, discovered_paths = await asyncio.gather(
            cls.scan_ports(target, is_deep=is_deep),
            cls.discover_paths(target, is_deep=is_deep)
        )

        return {
            "open_ports": open_ports,
            "discovered_paths": discovered_paths,
            "total_open_ports": len(open_ports),
            "total_paths_found": len(discovered_paths)
        }