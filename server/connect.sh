#!/bin/bash
openssl s_client -connect 127.0.0.1:44330 -debug -CAfile cert.pem 