FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN pip install -e .  # Install package in development mode

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]