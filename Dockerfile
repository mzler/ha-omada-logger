ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base-python:3.12-alpine3.20
FROM ${BUILD_FROM}

ENV LANG=C.UTF-8 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    sqlite \
    curl \
    jq

# Install Python requirements
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt

# Copy application files
COPY run.sh /run.sh
RUN chmod a+x /run.sh

COPY app.py /app/app.py

EXPOSE 8099 5514/udp

CMD ["/run.sh"]
