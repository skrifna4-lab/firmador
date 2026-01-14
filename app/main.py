from fastapi import FastAPI, HTTPException
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
    """Genera el certificado auto-firmado directamente en el VPS"""
    key_path = os.path.join(CERT_DIR, f"{alias}.key")
    cert_path = os.path.join(CERT_DIR, f"{alias}.crt")
    final_pem = os.path.join(CERT_DIR, f"{alias}.pem")

    cmd = (
        f'openssl req -x509 -newkey rsa:2048 -keyout "{key_path}" '
        f'-out "{cert_path}" -days 365 -nodes -subj "/C=PE/ST=Lima/L=Lima/O=Pruebas/CN={alias}"'
    )
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Error OpenSSL: {proc.stderr}")

    # Unimos ambos archivos en el .pem que usará el firmador
    with open(key_path, "r") as fkey, open(cert_path, "r") as fcrt, open(final_pem, "w") as fff:
        fff.write(fkey.read() + "\n" + fcrt.read())
            
    return {"status": "Certificado creado con éxito", "alias": alias}

@app.post("/firmar-xml")
async def firmar_xml(xml_base64: str, alias: str):
    """Firma el XML con algoritmos específicos aceptados por SUNAT"""
    pem_path = os.path.join(CERT_DIR, f"{alias}.pem")
    if not os.path.exists(pem_path):
        raise HTTPException(status_code=404, detail="No existe el certificado. Usa /generar-auto")

    try:
        xml_decoded = base64.b64decode(xml_base64).decode('utf-8')
        root = limpiar_xml(xml_decoded)
        
        with open(pem_path, "rb") as f:
            cert_data = f.read()

        # CONFIGURACIÓN CRÍTICA PARA EVITAR "Unknown transform algorithm"
        signer = XMLSigner(
            method=methods.enveloped, # Obligatorio para SUNAT
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256"
        )
        
        # Firmamos de la forma más simple posible (solo X509Data)
        signed_root = signer.sign(
            root, 
            key=cert_data, 
            cert=cert_data,
            always_add_key_value=False # SUNAT prefiere NO tener KeyValue
        )
        
        xml_firmado = etree.tostring(signed_root, xml_declaration=True, encoding="UTF-8")
        
        return {
            "xml_firmado": base64.b64encode(xml_firmado).decode('utf-8'),
            "status": "success"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en firma: {str(e)}")
