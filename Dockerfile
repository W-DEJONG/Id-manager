FROM python:3.8.1

WORKDIR /usr/src/app

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD gunicorn "manager:create_app()" --timeout=${TIMEOUT:-300} --bind 0.0.0.0:8000 --workers=${WORKERS:-1} --threads=${THREADS:-0 }
