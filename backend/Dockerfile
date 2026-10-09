# SECURITY: Multi-stage build ensures build tools (like compiler) are omitted from the production image
FROM golang:1.27-alpine AS builder

WORKDIR /app
COPY go.mod ./
COPY . .

# Retrieve dependencies and generate go.sum
RUN go mod tidy

# SECURITY: Build a statically linked binary. 
# -w -s flags strip DWARF debugging info to prevent information leakage if reverse-engineered.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o server .

# SECURITY: Final image uses alpine instead of a heavy base image, reducing the attack surface.
# (Distroless or scratch is even better, but alpine allows for basic debugging if needed)
FROM alpine:3.18

# SECURITY: Run as a non-root user. 
# Running processes as root inside containers is a major security risk.
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

WORKDIR /app
COPY --from=builder /app/server .

EXPOSE 8080
CMD ["./server"]
