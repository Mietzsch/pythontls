To open wireshark:

```bash
wireshark
```

Then filter the server: tcp.port == 44330

To use openssl to connect to google:

```bash
openssl s_client -tls1_3 -servername google.com -connect 142.251.36.238:443
```