FROM python:3.13-alpine

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py app.py

EXPOSE 5050
CMD ["flask", "run", "--host=0.0.0.0", "--port=5050"]
