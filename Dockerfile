FROM python:3.12-slim

WORKDIR /app

# Install system deps for possible GUI or crypto if needed (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default: headless mode. Override with --gui if you have a display.
# Port 162 needs privileges; use 1162 or map carefully.
EXPOSE 1162/udp 4840/tcp

ENV SNMP_AUTH_KEY="" \
    SNMP_PRIV_KEY=""

CMD ["python", "-m", "snmp2opcua", "-c", "config.yaml", "--port", "1162"]
