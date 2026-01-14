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
    cer_path = os.path.join(CERT_DIR, f"{alias}.cer")
    
    # 1. Comando OpenSSL con extensiones para SUNAT (Digital Signature y Non Repudiation)
    # Agregamos -addext para que el certificado sea legalmente de "Firma"
    cmd = (
        f'openssl req -x509 -newkey rsa:2048 -keyout "{key_path}" -out "{cert_path}" '
        f'-days 365 -nodes -subj "/C=PE/L=Lima/O=INVERSIONES HASBUN/CN={alias}" '
        f'-addext "keyUsage = critical, digitalSignature, nonRepudiation"'
    )
    
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        return {"error": "Fallo al generar", "detalle": result.stderr}

    # 2. Creamos el .cer (es una copia en formato DER que SUNAT prefiere)
    # Convertimos el CRT (PEM) a CER (DER) para asegurar compatibilidad total
    cmd_convert = f'openssl x509 -in "{cert_path}" -outform DER -out "{cer_path}"'
    subprocess.run(cmd_convert, shell=True)

    return {
        "message": "Generados correctamente",
        "archivos": [f"{alias}.key", f"{alias}.crt", f"{alias}.cer"],
        "instruccion": "Sube el .cer al portal SOL de SUNAT"
    }

@app.get("/cert/descargar/{alias}/{ext}")
async def descargar(alias: str, ext: str):
    # Soporta ext: key, crt, cer
    file_path = os.path.join(CERT_DIR, f"{alias}.{ext}")
    if os.path.exists(file_path):
        # Forzamos la descarga del archivo
        return FileResponse(file_path, filename=f"{alias}.{ext}")
    raise HTTPException(status_code=404, detail="Archivo no encontrado")
