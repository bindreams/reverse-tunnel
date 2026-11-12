#!/bin/sh
# lego's "exec" DNS provider: records the call and succeeds. Pebble accepts every challenge.
echo "$*" >> /acme/dns-exec.log
