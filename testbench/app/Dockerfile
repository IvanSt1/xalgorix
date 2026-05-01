FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN mkdir -p /app/logs /app/data

EXPOSE 8000

ENV PYTHONUNBUFFERED=1

CMD ["python", "app.py"]
