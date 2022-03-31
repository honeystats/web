FROM python:3.9
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY *.py .
COPY *.html .
CMD ["python3", "/app/adminwebsite.py"]
