FROM golang:alpine AS build-env
RUN apk add --no-cache git build-base openssl
COPY go.mod /src/
COPY go.sum /src/
RUN cd /src && go mod download
ADD . /src
RUN cd /src && ./gencert.sh
RUN cd /src && go build -o zendesk_login

FROM alpine
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build-env /src/zendesk_login /src/docker_entrypoint.sh /src/server.key /src/server.crt /src/
COPY --from=build-env /src/static /src/static
COPY --from=build-env /src/templates /src/templates
EXPOSE 8080
ENTRYPOINT ["/src/docker_entrypoint.sh"]
