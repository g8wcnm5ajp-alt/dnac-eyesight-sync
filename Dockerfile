FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py dnac_client.py eyesight_client.py sync_engine.py scheduler.py .
COPY templates/ templates/
COPY static/ static/

# Config, auth, history, and per-run logs -- bind-mounted read-write by
# Deploy.sh so they survive this container being redeployed.
VOLUME /data

# HTTPS cert -- mounted (and DNAC_EYESIGHT_SSL_CERT/_KEY only set) by
# Deploy.sh, matching forescout-lookup's own EM-hosted package.
VOLUME /certs

EXPOSE 5000

CMD ["python", "app.py"]
