FROM python:3.11-slim

WORKDIR /app

COPY c2/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 7860

CMD ["python", "c2/server.py"]
