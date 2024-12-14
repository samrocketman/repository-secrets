FROM alpine

SHELL ["/bin/sh", "-exc"]
RUN \
  apk add --no-cache bash openssl yq; \
  openssl genrsa -out /key 4096; \
  openssl rsa -in /key -pubout -outform pem -out /pub
COPY repository-secrets.sh /
ENV PRIVATE_KEY=/key PUBLIC_KEY=/pub

ENTRYPOINT ["/repository-secrets.sh"]
