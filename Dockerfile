FROM golang:1.26.5-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gym-booking .

FROM alpine:3.22

RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /out/gym-booking ./gym-booking

ENV PORT=10000
EXPOSE 10000
CMD ["./gym-booking"]