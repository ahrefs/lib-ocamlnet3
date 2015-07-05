#! /bin/sh

mkdir -p certs
cd certs

### CA

certtool --generate-privkey > x509-ca-key.pem

cat <<EOF > x509-ca.templ
cn = 'GnuTLS Test CA'
ca
cert_signing_key
EOF

certtool \
  --generate-self-signed \
  --load-privkey x509-ca-key.pem \
  --template x509-ca.templ \
  --outfile x509-ca.pem


### Server key

certtool --generate-privkey > x509-server-key.pem

cat <<EOF > x509-server.templ
cn = 'localhost'
tls_www_server
encryption_key
signing_key
dns_name = localhost
EOF

certtool \
  --generate-certificate \
  --load-privkey x509-server-key.pem \
  --load-ca-certificate x509-ca.pem \
  --load-ca-privkey x509-ca-key.pem \
  --template x509-server.templ \
  --outfile x509-server.pem


