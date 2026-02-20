FROM python:3.11-slim

WORKDIR /app

# Installation des outils de scan
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    unzip \
    nikto \
    && rm -rf /var/lib/apt/lists/*

# Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip \
    && unzip nuclei_3.1.0_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.1.0_linux_amd64.zip

# Templates Nuclei (community)
RUN nuclei -update-templates -silent || true

# Trivy
RUN wget -q https://github.com/aquasecurity/trivy/releases/download/v0.48.0/trivy_0.48.0_Linux-64bit.tar.gz \
    && tar xzf trivy_0.48.0_Linux-64bit.tar.gz \
    && mv trivy /usr/local/bin/ \
    && rm trivy_0.48.0_Linux-64bit.tar.gz

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "-m", "uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8001"]
