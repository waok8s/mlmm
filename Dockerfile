FROM python:3.11-slim-buster

WORKDIR /opt/app
COPY requirements.txt /opt/app/requirements.txt
RUN apt-get update \
    && apt-get -y upgrade \
    && pip3 install pip --upgrade \
    && pip3 install setuptools --upgrade \
    &&  pip3 install -r requirements.txt
COPY mlmm /opt/app/mlmm

ENV PYTHONUNBUFFERED 1
EXPOSE 8000
CMD ["./gunicorn", "--workers", "1", "--threads", "2", "--bind", ":8000", "--access-logfile", "-", "mlmm.app:create_app()"]
