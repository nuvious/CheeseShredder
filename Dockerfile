FROM python:3.11-alpine

WORKDIR /app
COPY . .
RUN pip install .
WORKDIR /workspace
RUN rm -rf /app

ENTRYPOINT [ "cheeseshredder" ]
