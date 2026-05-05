FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    curl \
    git \
    vim \
    unzip \
    software-properties-common \
    gnupg \
    lsb-release \
    python3 \
    python3-pip \
    ssh \
    nano \
    && rm -rf /var/lib/apt/lists/*

# Ansible
RUN pip3 install --upgrade ansible

# Terraform
RUN curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
    > /etc/apt/sources.list.d/hashicorp.list && \
    apt update && apt install -y terraform

WORKDIR /root

CMD ["bash"]
#Fin
