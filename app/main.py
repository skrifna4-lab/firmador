from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
import os, subprocess

app = FastAPI(title="Generador de Certificados SUNAT - Hasbun")

CERT_DIR = "/app/certs"
os.makedirs(CERT_DIR, exist_ok=True)

@app.post("/cert/generar-auto")
async def generar_auto(
    alias: str = Query(..., description="Nombre del archivo (ej: certificadov1)"),
    ruc: str = Query(..., description="RUC de la empresa"),
    razon_social: str = Query(..., description="Nombre o Razón Social de la empresa")
):
    """
    Genera los 3 archivos (.key, .crt, .cer) con los permisos de 
    FIRMA DIGITAL que SUNAT exige.
    """
    key_path = os.path.join(CERT_DIR, f"{alias}.key")
    crt_path = os.path.join(CERT_DIR, f"{alias}.crt")
    cer_path = os.path.join(CERT_DIR, f"{alias}.cer")
    
    # El campo CN suele llevar el RUC para mayor compatibilidad con SUNAT
    # El campo O lleva la Razón Social
    subject = f"/C=PE/L=Lima/O={razon_social}/CN={ruc}"
    
    # COMANDO MAESTRO: Genera certificado con uso de firma digital y no repudio
    cmd = (
        f'openssl req -x509 -newkey rsa:2048 -keyout "{key_path}" -out "{crt_path}" '
        f'-days 365 -nodes -subj "{subject}" '
        f'-addext "keyUsage = critical, digitalSignature, nonRepudiation"'
    )
    
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Error OpenSSL: {result.stderr}")

    # Convertir a formato .CER (DER binario) que es el que SUNAT acepta sin errores
    cmd_convert = f'openssl x509 -in "{crt_path}" -outform DER -out "{cer_path}"'
    subprocess.run(cmd_convert, shell=True)

    return {
        "status": "success",
        "empresa": razon_social,
        "ruc": ruc,
        "archivos_generados": [f"{alias}.key", f"{alias}.crt", f"{alias}.cer"],
        "download_urls": {
            "key": f"/cert/descargar/{alias}/key",
            "crt": f"/cert/descargar/{alias}/crt",
            "cer": f"/cert/descargar/{alias}/cer"
        }
    }

@app.get("/cert/descargar/{alias}/{ext}")
async def descargar(alias: str, ext: str):
    # Validamos extensiones permitidas
    if ext not in ["key", "crt", "cer"]:
        raise HTTPException(status_code=400, detail="Extensión no permitida")
        
    file_path = os.path.join(CERT_DIR, f"{alias}.{ext}")
    if os.path.exists(file_path):
        return FileResponse(
            path=file_path, 
            filename=f"{alias}.{ext}",
            media_type='application/octet-stream'
        )
    raise HTTPException(status_code=404, detail="El archivo solicitado no existe")
