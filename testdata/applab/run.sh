#!/bin/bash
# Runs one lab app, attacks it, and collects the logs it wrote. Usage: run.sh <app> [args...]
set -u
cd "$(dirname "$0")"
app="$1"; shift
net=omamori-applab
out="out/$app"
rm -rf "$out"; mkdir -p "$out"
docker network inspect $net >/dev/null 2>&1 || docker network create --internal --label omamori.lab=1 $net >/dev/null
docker rm -f "lab-$app" applab-attacker >/dev/null 2>&1
docker run -d --name "lab-$app" --hostname "$app" --network $net --label omamori.lab=1 -e TZ=UTC "omamori-applab-$app" "$@" >/dev/null
docker run -d --name applab-attacker --network $net --label omamori.lab=1 omamori-lab-attacker:1 >/dev/null
for i in $(seq 1 90); do
  code=$(docker exec applab-attacker curl -s -o /dev/null -w '%{http_code}' "http://lab-$app:8080/api/items" 2>/dev/null)
  [ "$code" != "000" ] && [ -n "$code" ] && break
  sleep 2
done
echo "$app answered with $code after $i tries"
docker exec -i applab-attacker bash -s "lab-$app" < attack.sh
sleep 3
docker logs -t "lab-$app" > "$out/docker-timestamps.log" 2>&1
id=$(docker inspect -f '{{.Id}}' "lab-$app")
colima ssh -- sudo cat "/var/lib/docker/containers/$id/$id-json.log" > "$out/docker-json.log"
case "$app" in
  spring) docker cp "lab-$app:/logs/." "$out/tomcat" >/dev/null ;;
  laravel) docker cp "lab-$app:/srv/lab/storage/logs/laravel.log" "$out/laravel.log" >/dev/null ;;
esac
docker rm -f "lab-$app" applab-attacker >/dev/null
wc -l "$out"/* 2>/dev/null | tail -n +1
