FROM ubuntu:20.04

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    libc6-dev \
    libcjson-dev \
    libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source files
COPY . .

# Compile the application (excluding main.c, using only server.c)
RUN gcc -o main main.c src/wordle_core.c src/solver_fast.c src/solver_efficient.c -Iinclude -lm -pthread -lcjson -lcurl

# Expose port
EXPOSE 8080

# Run the server
CMD ["./main"]