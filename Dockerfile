FROM alpine

SHELL ["/bin/sh", "-exc"]
COPY repository-secrets.sh /bin/
RUN \
  apk add --no-cache bash openssl yq; \
  openssl genrsa -out /key 4096; \
  openssl rsa -in /key -pubout -outform pem -out /pub; \
  chmod 755 /bin/repository-secrets.sh

ENTRYPOINT ["repository-secrets.sh", "-k", "/key", "-p", "/pub"]
