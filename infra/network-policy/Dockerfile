FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
RUN apt-get update && apt-get install -y --no-install-recommends iptables && rm -rf /var/lib/apt/lists/*
COPY firewall.py /firewall.py
COPY fixture-egress.json /etc/aegistrace/egress.json
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["python", "/firewall.py"]
