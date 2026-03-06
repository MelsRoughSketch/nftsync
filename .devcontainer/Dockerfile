FROM rockylinux:9

# Install core utilities and development tools
RUN yum groupinstall -y --allowerasing "Core" && \
    yum install -y --allowerasing \
    git \
    make \
    wget \
    curl \
    bind-utils \
    bash-completion \
    procps-ng \
    iproute \
    net-tools \
    which \
    nftables \
    tcpdump \
    strace \
    && rm -rf /var/cache/yum/*

# Install Go 1.26
RUN wget https://go.dev/dl/go1.26.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.26.0.linux-amd64.tar.gz && \
    rm go1.26.0.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin

WORKDIR /workspace
