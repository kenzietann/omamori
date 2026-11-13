# The server that the lab attacks: a small Debian with the services of a web server. Made by omamori lab.
FROM debian:trixie-slim
LABEL omamori.lab=1
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    openssh-server rsyslog cron nginx sudo curl ca-certificates procps iproute2 tcpdump \
 && rm -rf /var/lib/apt/lists/*
# alice has a password that is guessed in the attack. deploy has one that is not.
RUN useradd -m -s /bin/bash alice && echo 'alice:Summer2026!' | chpasswd \
 && useradd -m -s /bin/bash deploy && echo 'deploy:N0t-guessable-9f3k' | chpasswd \
 && mkdir -p /run/sshd /var/lib/omamori-lab \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && echo 'PerSourcePenalties no' >> /etc/ssh/sshd_config \
 && sed -i 's/^module(load="imklog")/#&/' /etc/rsyslog.conf \
 && echo '<html><body>web01</body></html>' > /var/www/html/index.html \
 && mkdir -p /var/www/html/uploads && chown alice /var/www/html/uploads
COPY start.sh /start.sh
RUN chmod 755 /start.sh
CMD ["/start.sh"]
