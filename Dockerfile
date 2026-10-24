FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /donobox .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /donobox /donobox
ENTRYPOINT ["/donobox", "-mafile", "/config/account.maFile"]
