FROM python:3.12-slim

LABEL maintainer="Chandan Pandey"
LABEL description="Aegis — Modular Offensive Security Platform"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    netcat-openbsd \
    smbclient \
    hydra \
    sqlmap \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

# Create data/config directories so aegis can find them
RUN mkdir -p data/logs data/reports data/evidence data/exports data/screenshots config

# Tell Aegis where the project root is (fixes 'Config not found' in Docker)
ENV AEGIS_PROJECT_DIR=/app

# Ensure main.py is importable when running as installed package
ENV PYTHONPATH=/app:${PYTHONPATH}

ENTRYPOINT ["aegis"]
CMD ["--help"]
