FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY relay_server.py licensedb.py otp.py admin.py control.html manifest.json sw.js icon-192.png icon-512.png icon-512-maskable.png ./

COPY seller.html seller.css seller.js ./

ENV PORT=8080

EXPOSE 8080

CMD ["python", "relay_server.py"]
