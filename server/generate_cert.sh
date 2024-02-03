#!/bin/bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost" -addext extendedKeyUsage=serverAuth