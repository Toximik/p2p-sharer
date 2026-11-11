FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SHARER_DATA=/data \
    SHARER_HOST=0.0.0.0 \
    SHARER_PORT=8080 \
    SHARER_FILES_ROOT=/srv/files

ARG UID=1000
ARG GID=1000
RUN groupadd -g "$GID" sharer && useradd -u "$UID" -g sharer -M -d /app -s /usr/sbin/nologin sharer

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /data /srv/files && chown sharer:sharer /data

USER sharer
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"SHARER_PORT\"]}/static/style.css', timeout=4)" || exit 1

CMD ["python", "app.py"]
