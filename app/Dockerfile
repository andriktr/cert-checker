FROM python:3.12-slim

RUN apt-get update && apt-get install -y curl openssl

RUN mkdir /app

WORKDIR /app

COPY requirements.txt .

RUN python -m pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt && rm requirements.txt

COPY cert-checker.py .

CMD ["python", "cert-checker.py"]
