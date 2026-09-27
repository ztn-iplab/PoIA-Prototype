FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY downstream ./downstream

ENV POIA_DATA_DIR=/data
# POIA_SESSION_SECRET is deliberately NOT defaulted here: app/settings.py refuses
# to start without a real secret (or POIA_TEST_MODE). Set it via compose/env at
# run time -- never bake a guessable literal into the image.

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload", "--reload-dir", "/app/app"]
