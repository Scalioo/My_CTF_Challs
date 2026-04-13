#!/bin/sh

EXEC="./server.sage"
PORT=2020

socat -dd -T3600 tcp-l:$PORT,reuseaddr,fork,keepalive, exec:"sage $EXEC",stderr,sighup,sigint,sigquit