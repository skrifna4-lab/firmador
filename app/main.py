from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
import os, subprocess

app = FastAPI()
CERT_DIR = "/app/certs"
os.makedirs(CERT_DIR, exist_ok=True)

@app.post("/cert/generar-auto")
async def generar_auto(alias: str):
    key_path = os.path.join(CERT_DIR, f"{alias}.key")
    cert_path = os.path.join(CERT_DIR, f"{alias}.crt")
    # Genera certificado y llave
    cmd = f'openssl req -x509 -newkey rsa:2048 -keyout "{key_path}" -out "{cert_path}" -days 365 -nodes -subj "/C=PE/L=Lima/O=Pruebas/CN={alias}"'
    subprocess.run(cmd, shell=True, capture_output=True)
    return {"message": "Generado. Ahora puedes descargarlos."}

@app.get("/cert/descargar/{alias}/{ext}")
async def descargar(alias: str, ext: str):
    # ext puede ser 'key' o 'crt'
    file_path = os.path.join(CERT_DIR, f"{alias}.{ext}")
    if os.path.exists(file_path):
        return FileResponse(file_path)
    raise HTTPException(status_code=404, detail="Archivo no encontrado")
