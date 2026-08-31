# Sentinel Enterprise NIDS & SIEM Container
FROM python:3.11-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir .

EXPOSE 5140/udp 8080/tcp

ENTRYPOINT ["python", "-m", "sentinel.daemon.cli"]
CMD ["--simulate-attacks"]
