FROM python:3.10-slim

# Instalación de dependencias del sistema
RUN apt-get update && apt-get install -y \
    openssl \
    libxml2-dev \
    libxslt-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalación de librerías Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Carpeta para certificados persistentes
RUN mkdir -p /app/certs

COPY . .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]