#!/usr/bin/env bash
#set -e

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=US/O=Sun Microsystems/OU=JavaSoft/CN=Duke"
