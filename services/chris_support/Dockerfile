FROM python:3.12-slim
WORKDIR /app
COPY requirements-chris.txt ./requirements-chris.txt
RUN pip install --no-cache-dir -r requirements-chris.txt \
    && useradd --create-home --uid 10001 app
COPY services/chris_support/ ./services/chris_support/
COPY services/assets/ ./services/assets/
COPY services/threats/ ./services/threats/
COPY services/reports/ ./services/reports/
USER app
EXPOSE 8000
CMD ["uvicorn", "services.assets.main:app", "--host", "0.0.0.0", "--port", "8000"]
