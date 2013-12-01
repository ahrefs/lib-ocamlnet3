#! /bin/sh

mkdir -p certs

### CA

certtool --generate-privkey > certs/x509-ca-key.pem

cat <<EOF > certs/ca.templ
cn = 'GnuTLS Test CA'
ca
cert_signing_key
EOF

certtool \
  --generate-self-signed \
  --load-privkey certs/x509-ca-key.pem \
  --template certs/ca.templ \
  --outfile certs/x509-ca.pem


### Server key

certtool --generate-privkey > certs/x509-server-key.pem

cat <<EOF > certs/server.templ
cn = 'localhost'
tls_www_server
encryption_key
signing_key
dns_name = localhost
EOF

certtool \
  --generate-certificate \
  --load-privkey certs/x509-server-key.pem \
  --load-ca-certificate certs/x509-ca.pem \
  --load-ca-privkey certs/x509-ca-key.pem \
  --template certs/server.templ \
  --outfile certs/x509-server.pem

### Second server key

certtool --generate-privkey > certs/x509-server2-key.pem

cat <<EOF > certs/server2.templ
cn = 'otherhost'
tls_www_server
encryption_key
signing_key
dns_name = otherhost
EOF

certtool \
  --generate-certificate \
  --load-privkey certs/x509-server2-key.pem \
  --load-ca-certificate certs/x509-ca.pem \
  --load-ca-privkey certs/x509-ca-key.pem \
  --template certs/server2.templ \
  --outfile certs/x509-server2.pem

### Client key

certtool --generate-privkey > certs/x509-client-key.pem

cat <<EOF > certs/client.templ
cn = 'test client'
tls_www_client
encryption_key
signing_key
EOF

certtool \
  --generate-certificate \
  --load-privkey certs/x509-client-key.pem \
  --load-ca-certificate certs/x509-ca.pem \
  --load-ca-privkey certs/x509-ca-key.pem \
  --template certs/client.templ \
  --outfile certs/x509-client.pem

cat <<EOF > certs/pkcs12.templ
pkcs12_key_name = 'client key'
EOF

certtool \
  --to-p12 \
  --load-ca-certificate certs/x509-ca.pem \
  --load-privkey certs/x509-client-key.pem \
  --load-certificate certs/x509-client.pem \
  --template certs/pkcs12.templ \
  --password 'my password' \
  --outder --outfile certs/x509-client.p12
