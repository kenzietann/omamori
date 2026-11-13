# The attacker of the lab. It only knows the address of the lab server. Made by omamori lab.
FROM debian:trixie-slim
LABEL omamori.lab=1
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-client sshpass curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
