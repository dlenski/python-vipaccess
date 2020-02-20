#
# Dockerfile for an alpine-based python container for python-vipaccess
#
# Create named image to make it easier to refer to
#     "docker build . -t python-vipaccess"
# Run vipaccess to generate tokens with 
#     "docker run python-vipaccess provision -p"
# Generate ANSI graphics QR code from generated otpauth string
#     "docker run --entrypoint "qrencode" python-vipaccess -t ANSI256 <otpauth://...>"
#

FROM python:3-alpine

LABEL maintainer "Kayvan Sylvan <kayvansylvan@gmail.com>"

COPY . /usr/src/
WORKDIR /usr/src

RUN apk add --no-cache --virtual .build-deps \
    gcc libc-dev libxml2-dev libxslt-dev \
  && apk add --no-cache libxml2 libxslt \
  && apk add --no-cache libqrencode \
  && pip3 install --no-cache-dir . \
  && find /usr/local -name *.pyo -o -name *.pyc -exec rm -f '{}' \; \
  && apk del .build-deps && touch /root/.vipaccess

ENTRYPOINT ["/usr/local/bin/vipaccess"]
