# wolfSSL Hybrid TLS 1.3

This repository contains a minimal TLS Hybrid TLS 1.3 server and client using wolfSSL (ML-KEM key exchange).

## Setup

```bash
sudo apt update
sudo apt install -y build-essential git cmake pkg-config openssl
```

## Install wolfSSL

Build and install from source (for TLS 1.3 and ML-KEM):

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
mkdir build && cd build
cmake -DWOLFSSL_TLS13=ON -DWOLFSSL_DILITHIUM=ON -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo make install
sudo ldconfig
```

## Generate Test Certificates

The repository includes a `certs/` folder. To generate new test certs (MK-KEM):

```bash
# Generated CA with extensions
cat > ca_ext.cnf << 'EOF'
basicConstraints=critical,CA:TRUE
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
EOF

openssl req -x509 -new -newkey mldsa44 -keyout ca-key.pem -out ca-cert.pem -nodes -subj "/CN=127.0.0.1" -days 365 -addext "basicConstraints=critical,CA:TRUE" -addext "subjectKeyIdentifier=hash"

# generate server cert
cat > server_ext.cnf << 'EOF'
authorityKeyIdentifier=keyid,issuer
subjectKeyIdentifier=hash
basicConstraints=CA:FALSE
subjectAltName=IP:127.0.0.1
EOF

openssl genpkey -algorithm mldsa44 -out server-key.pem
openssl req -new -key server-key.pem -out server.csr -subj "/CN=[REPLACE WITH SERVER IP]"
openssl x509 -req -in server.csr -out server-cert.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -days 365 -extfile server_ext.cnf

# Check keys
openssl x509 -in ca-cert.pem -noout -text | grep -A2 "Subject Key"
openssl x509 -in server-cert.pem -noout -text | grep -A2 "Authority Key"
```

## Build & Run

```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DWOLFSSL_ROOT=/usr/local/include/wolfssl
cmake --build . --config Release

# Run server (background)
./server &

# Run client
./client
```