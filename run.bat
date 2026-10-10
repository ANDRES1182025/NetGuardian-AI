@echo off
TITLE CyberSentinel Backend Launcher
color 0A
echo ===================================================
echo    INICIANDO EL BACKEND DE CYBERSENTINEL (FASTAPI)
echo ===================================================
echo.

:: Activar el entorno virtual automáticamente
echo [1/2] Activando entorno virtual...
call venv\Scripts\activate

echo.
echo [2/2] Lanzando servidor Uvicorn con recarga en vivo...
echo El servidor estara disponible en: http://127.0.0.1:8000
echo (Presiona Ctrl + C si deseas apagar el servidor en cualquier momento)
echo.

uvicorn main:app --reload

pause