# Backend + static frontend in one image. NOT VALIDATED in the build sandbox (no Docker available).
FROM python:3.12-slim

RUN useradd --create-home --uid 10001 deploylens
WORKDIR /app
COPY backend/app ./app
COPY backend/fixtures ./fixtures
COPY frontend ./frontend
RUN mkdir -p /app/data && chown -R deploylens:deploylens /app/data

ENV DEPLOYLENS_HOST=0.0.0.0 \
    DEPLOYLENS_PORT=8000 \
    DEPLOYLENS_DB=/app/data/deploylens.db \
    DEPLOYLENS_FRONTEND_DIR=/app/frontend \
    PYTHONUNBUFFERED=1

USER deploylens
EXPOSE 8000
CMD ["python", "-m", "app.main"]
