FROM python:3.9

ENV PYTHONUNBUFFERED 1

WORKDIR /app/
COPY requirements.txt /app/
ADD saml-django-demo /app/

RUN apt-get update
RUN apt-get install -y pkg-config libxml2-dev libxmlsec1-dev libxmlsec1-openssl

RUN pip install --upgrade pip \
    pip install -r requirements.txt

EXPOSE 8080
CMD python manage.py runserver 0.0.0.0:8080
