FROM python:3.14


WORKDIR /code


COPY ./requirements.txt /code/requirements.txt


RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt


COPY ./pyproject.toml /code/pyproject.toml
COPY ./app /code/app
COPY ./tests /code/tests


CMD ["fastapi", "dev", "app/main.py", "--host", "0.0.0.0", "--port", "80"]
