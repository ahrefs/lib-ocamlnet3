#! /bin/sh

mkdir -p certs

### CA

certtool --generate-privkey > ca.key

cat <<EOF > ca.templ
cn = 'GnuTLS Test CA'
ca
cert_signing_key
EOF

certtool \
  --generate-self-signed \
  --load-privkey ca.key \
  --template ca.templ \
  --outfile ca.crt


### Server key

certtool --generate-privkey > server.key

cat <<EOF > server.templ
cn = 'localhost'
tls_www_server
encryption_key
signing_key
dns_name = localhost
EOF

certtool \
  --generate-certificate \
  --load-privkey server.key \
  --load-ca-certificate ca.crt \
  --load-ca-privkey ca.key \
  --template server.templ \
  --outfile server.crt

### Client key

certtool --generate-privkey > client.key

cat <<EOF > client.templ
cn = 'test client'
tls_www_client
encryption_key
signing_key
EOF

certtool \
  --generate-certificate \
  --load-privkey client.key \
  --load-ca-certificate ca.crt \
  --load-ca-privkey ca.key \
  --template client.templ \
  --outfile client.crt
