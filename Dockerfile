FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY aib/ ./aib/

RUN pip install --no-cache-dir .

EXPOSE 8420

ENV AIB_SECRET_KEY=change-me-in-production
ENV AIB_STORAGE_PATH=/data/passports

VOLUME /data

CMD ["uvicorn", "aib.main:app", "--host", "0.0.0.0", "--port", "8420"]
