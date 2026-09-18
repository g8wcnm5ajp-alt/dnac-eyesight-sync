FROM python:3.12-slim

WORKDIR /app

# openssh-client: the Setup page reaches this EM's fw-helper.sh through
# the restricted key Deploy.sh registers; openssl: the Certificates page
# reads cert details with it.
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client openssl     && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py dnac_client.py eyesight_client.py sync_engine.py scheduler.py fw_client.py .
COPY templates/ templates/
COPY static/ static/

# Config, auth, history, and per-run logs -- bind-mounted read-write by
# Deploy.sh so they survive this container being redeployed.
VOLUME /data

# HTTPS cert -- mounted (and DNAC_EYESIGHT_SSL_CERT/_KEY only set) by
# Deploy.sh, matching forescout-lookup's own EM-hosted package.
VOLUME /certs

# The app's restricted SSH key for fw-helper.sh -- mounted read-only by
# Deploy.sh (keys/ next to it on the EM).
VOLUME /keys

EXPOSE 5000

CMD ["python", "app.py"]
