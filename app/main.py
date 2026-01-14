from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os, base64, subprocess
from signxml import XMLSigner, methods
from lxml import etree
from .utils import limpiar_xml

app = FastAPI(title="Firmador Digital Dokploy")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

CERT_DIR = "/app/certs"
os.makedirs(CERT_DIR, exist_ok=True)

@app.get("/")
def home():
    return {"status": "Servicio de Firma Operativo"}

@app.post("/cert/generar-auto")
async def generar_auto(alias: str):
    key_path = os.path.join(CERT_DIR, f"{alias}.key")
    cert_path = os.path.join(CERT_DIR, f"{alias}.crt")
    final_pem = os.path.join(CERT_DIR, f"{alias}.pem")
    cmd = f'openssl req -x509 -newkey rsa:2048 -keyout "{key_path}" -out "{cert_path}" -days 365 -nodes -subj "/C=PE/ST=Lima/L=Lima/O=Pruebas/CN={alias}"'
    subprocess.run(cmd, shell=True, capture_output=True)
    with open(key_path, "r") as fk, open(cert_path, "r") as fc, open(final_pem, "w") as ff:
        ff.write(fk.read() + "\n" + fc.read())
    return {"status": "Certificado creado"}

@app.post("/firmar-xml")
async def firmar_xml(xml_base64: str, alias: str):
    pem_path = os.path.join(CERT_DIR, f"{alias}.pem")
    if not os.path.exists(pem_path):
        raise HTTPException(status_code=404, detail="No existe el certificado.")

    try:
        xml_decoded = base64.b64decode(xml_base64).decode('utf-8')
        root = limpiar_xml(xml_decoded)
        with open(pem_path, "rb") as f:
            cert_data = f.read()

        # Configuración estricta
        signer = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256"
        )
        
        # Firmar
        signed_root = signer.sign(root, key=cert_data, cert=cert_data, always_add_key_value=False)
        
        # --- CORRECCIÓN CRÍTICA PARA SUNAT ---
        # Buscamos el tag Transform y forzamos el algoritmo estándar
        for transform in signed_root.xpath(".//ds:Transform", namespaces={'ds': 'http://www.w3.org/2000/09/xmldsig#'}):
            transform.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
        
        xml_firmado = etree.tostring(signed_root, xml_declaration=True, encoding="UTF-8")
        return {"xml_firmado": base64.b64encode(xml_firmado).decode('utf-8'), "status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
