FROM python:3-alpine

RUN apk update && \
    apk add socat build-base python3-dev && \
    pip install pycryptodome && \
    apk del build-base python3-dev

COPY ./ /dist

WORKDIR /dist

RUN chmod +x entrypoint.sh server.py 

EXPOSE 1025

ENTRYPOINT ["./entrypoint.sh"]