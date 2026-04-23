FROM python:alpine3.22

RUN apk add --no-cache git build-base

RUN addgroup -S badsecrets && adduser -S -D -h /home/badsecrets badsecrets badsecrets

WORKDIR /usr/local/src/badsecrets

COPY . .

RUN pip install --no-cache-dir ./

USER badsecrets

ENTRYPOINT ["badsecrets"]
CMD ["-h"]
