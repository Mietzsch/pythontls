#!/bin/bash
openssl s_server -key key.pem -cert cert.pem -accept 44330 -www -tls1_3 -rev -debug