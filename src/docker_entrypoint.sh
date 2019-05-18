#!/usr/bin/env sh
cp /src/zendesk_login /app/
cp -r /src/templates /src/static /app/
[ -f /app/server.crt ] || cp /src/server.crt /app/
[ -f /app/server.key ] || cp /src/server.key /app/
cd /app && ./zendesk_login
