# Step 1: Build stage
FROM golang:1.23-alpine as build

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download the dependencies. Dependencies will be cached if the go.mod and go.sum are not changed
RUN go mod tidy

# Copy the entire project
COPY . .

# Build the Go app
RUN go build -o main .

# Step 2: Final stage (small image)
FROM alpine:latest

# Install PostgreSQL client (optional if you want to run DB operations from within the container)
RUN apk --no-cache add ca-certificates

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the pre-built binary file from the build stage
COPY --from=build /app/main .

# Expose port
EXPOSE 3000

# Command to run the executable
CMD ["./main"]
