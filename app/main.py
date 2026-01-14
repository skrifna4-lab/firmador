from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os, base64, subprocess
from signxml import XMLSigner, methods
from lxml import etree
from .utils import limpiar_xml

app = FastAPI(title="Firmador Digital Dokploy")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

CERT_DIR = "/app/certs"
os.makedirs(CERT_DIR, exist_ok=True)

@app.get("/")
def home():
    return {"status": "Servicio de Firma Operativo", "entorno": "VPS Dokploy"}

@app.post("/cert/generar-auto")
async def generar_auto(alias: str):
    """Genera llave y certificado y los une en un solo archivo PEM compatible"""
    key_path = os.path.join(CERT_DIR, f"{alias}.key")
    cert_only_path = os.path.join(CERT_DIR, f"{alias}.crt")
    final_pem_path = os.path.join(CERT_DIR, f"{alias}.pem")

    # 1. Generar la llave y el certificado por separado vía OpenSSL
    cmd = (
        f'openssl req -x509 -newkey rsa:2048 -keyout "{key_path}" '
        f'-out "{cert_only_path}" -days 365 -nodes -subj "/C=PE/ST=Lima/L=Lima/O=Pruebas/CN={alias}"'
    )
    
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Error creando cert: {proc.stderr}")

    # 2. UNIR AMBOS usando Python para asegurar compatibilidad total
    try:
        with open(key_path, "r") as fkey, open(cert_only_path, "r") as fcrt:
            key_data = fkey.read()
            cert_data = fcrt.read()
        
        with open(final_pem_path, "w") as ffinal:
            ffinal.write(key_data)
            ffinal.write("\n")
            ffinal.write(cert_data)
            
        return {"status": "Certificado y Llave generados y unidos", "alias": alias}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al unir archivos: {str(e)}")

@app.post("/convertir-pfx")
async def convertir_pfx(file: UploadFile = File(...), password: str = Form(...), alias: str = Form(...)):
    """Convierte un PFX externo a PEM en el VPS"""
    pfx_path = os.path.join(CERT_DIR, f"{alias}.pfx")
    pem_path = os.path.join(CERT_DIR, f"{alias}.pem")
    
    with open(pfx_path, "wb") as f:
        f.write(await file.read())

    cmd = f'openssl pkcs12 -in "{pfx_path}" -out "{pem_path}" -nodes -passin pass:"{password}"'
    resultado = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if resultado.returncode != 0:
        if os.path.exists(pfx_path): os.remove(pfx_path)
        raise HTTPException(status_code=400, detail=f"Error OpenSSL: {resultado.stderr}")

    return {"message": "Certificado PFX convertido a PEM", "alias": alias}

@app.post("/firmar-xml")
async def firmar_xml(xml_base64: str, alias: str):
    """Firma un XML usando el certificado guardado en el VPS"""
    pem_path = os.path.join(CERT_DIR, f"{alias}.pem")
    
    if not os.path.exists(pem_path):
        raise HTTPException(status_code=404, detail="Certificado no encontrado. Genere uno primero.")

    try:
        # Decodificar el XML recibido
        xml_decoded = base64.b64decode(xml_base64).decode('utf-8')
        root = limpiar_xml(xml_decoded)
        
        with open(pem_path, "rb") as f:
            cert_key_data = f.read()

        # Configurar firmante estándar SUNAT/UBL
        signer = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256"
        )
        
        # Firmar (El archivo PEM ahora contiene Private Key + Certificate)
        signed_root = signer.sign(root, key=cert_key_data, cert=cert_key_data)
        xml_firmado = etree.tostring(signed_root, xml_declaration=True, encoding="UTF-8")
        
        return {
            "xml_firmado": base64.b64encode(xml_firmado).decode('utf-8'),
            "status": "success"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en firma: {str(e)}")
