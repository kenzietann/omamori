#!/bin/bash
# Builds the image of every lab app. Images are tagged omamori-applab-<name>.
cd "$(dirname "$0")"
for app in express nest nestpino django flask fastapi golang spring aspnet laravel rails rust-axum rust-actix; do
  start=$(date +%s)
  if docker build -q -t "omamori-applab-$app" --label omamori.lab=1 "$app" > "build-$app.log" 2>&1; then
    echo "$app built in $(( $(date +%s) - start ))s"
  else
    echo "$app FAILED (see build-$app.log)"
  fi
done
