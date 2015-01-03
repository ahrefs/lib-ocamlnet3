#! /bin/sh

gnutls-serv \
  --x509cafile certs/x509-ca.pem \
  --x509keyfile certs/x509-server-key.pem \
  --x509certfile certs/x509-server.pem \
  --generate \
  --echo \
  --port 4242
