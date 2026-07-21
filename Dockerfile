FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ripgrep tree findutils coreutils gawk sed grep file unzip \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash agent

WORKDIR /workspace
USER agent
CMD ["sleep", "infinity"]
