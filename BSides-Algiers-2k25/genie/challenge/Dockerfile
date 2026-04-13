FROM sagemath/sagemath:latest

USER root

RUN apt-get update && \
    apt-get install -y socat && \
    rm -rf /var/lib/apt/lists/*

COPY ./ /dist
WORKDIR /dist

RUN chmod +x entrypoint.sh server.sage
ENV PYTHONUNBUFFERED=1
# ENV TMPDIR=/tmp/sage_tmp
# RUN mkdir -p $TMPDIR

EXPOSE 2020

ENTRYPOINT ["./entrypoint.sh"]