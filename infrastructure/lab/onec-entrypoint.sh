#!/bin/sh
set -eu
agent=''
admin=''
cleanup() {
    [ -z "$agent" ] || kill -TERM "$agent" 2>/dev/null || :
    [ -z "$admin" ] || kill -TERM "$admin" 2>/dev/null || :
    wait 2>/dev/null || :
}
trap cleanup EXIT
trap 'exit 0' TERM INT
ragent -port 2540 -regport 2541 -range 2560:2591 -seclev 0 -d /lab/data &
agent=$!
ras cluster --port=2545 localhost:2540 &
admin=$!
while kill -0 "$agent" 2>/dev/null && kill -0 "$admin" 2>/dev/null; do sleep 1; done
exit 1
