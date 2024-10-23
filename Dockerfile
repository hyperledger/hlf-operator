FROM alpine:3.14

RUN \
    apk update && \
    apk add --no-cache curl ca-certificates shadow

COPY CREDITS /licenses/CREDITS
COPY LICENSE /licenses/LICENSE
LABEL name="HLF Operator" \
      vendor="Kung Fu Software <dviejo@kungfusoftware.es>" \
      maintainer="Kung Fu Software <dviejo@kungfusoftware.es>" \
      version="v1.1.0" \
      release="v1.1.0"

COPY charts /charts

COPY hlf-operator /hlf-operator

CMD ["/hlf-operator"]