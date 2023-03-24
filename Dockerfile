#
# Build stage using go-alpine
#
FROM golang:1.20-alpine as build

# install dependencies
RUN apk --no-cache add alpine-sdk 

# create golang repository
RUN mkdir -p /build-dir
WORKDIR /build-dir

# copy golang files
COPY go.mod ./
COPY go.sum ./
RUN go mod download -x
COPY *.go ./
RUN go build -ldflags="-w -s"

#
# Final stage using alpine and the built binary
# to ensure minimal footprint image.
#

FROM alpine:latest as application

COPY --from=build /build-dir/rz-silhouette-server /usr/bin/rz-silhouette-server

RUN adduser -D user

USER user

EXPOSE 9999

CMD [ "/usr/bin/rz-silhouette-server", "-config", "/config.yaml" ]

