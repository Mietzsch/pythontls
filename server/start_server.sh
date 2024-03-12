#!/bin/bash
openssl s_server -no_middlebox -key key.pem -cert cert.pem -accept 44330 -www -tls1_3 -rev -debug -keylogfile keys.txt