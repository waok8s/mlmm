FROM python:3.11-slim-buster

WORKDIR /opt/app
COPY requirements.txt /opt/app/requirements.txt
COPY test-requirements.txt /opt/app/test-requirements.txt
COPY setup.py /opt/app/setup.py
COPY mlmm /opt/app/mlmm
COPY data /opt/app/data
COPY tests /opt/app/tests

RUN pip3 install pip --upgrade \
    && pip3 install setuptools --upgrade \
    && pip3 install -r requirements.txt \
    && pip3 install -r test-requirements.txt \
    && pip3 install -e .

ENV PYTHONUNBUFFERED 1

WORKDIR /opt/app/tests
COPY pytest.ini /opt/app/tests/pytest.ini

ENTRYPOINT ["python3", "-m"]
