# wolfSSL TLS 1.3 — Hybrid ML-KEM Implementation

A TLS 1.3 server and client using wolfSSL with hybrid post-quantum key exchange (P-256 + ML-KEM-768).

## Key Exchange

- **Key Exchange:** SecP256r1MLKEM768 (P-256 ECDHE + ML-KEM-768 hybrid)
- **Cipher Suite:** TLS_AES_256_GCM_SHA384
- **Protocol:** TLS 1.3 only

## Prerequisites

- **Visual Studio 2022 Community** (or higher) with the "Desktop development with C++" workload
- **Git** (includes Git Bash, needed for OpenSSL cert generation)
- **wolfSSL source** cloned from GitHub (v5.9.0 or later required for ML-KEM support)

## Setup Instructions

### 1. Clone wolfSSL

```
git clone https://github.com/wolfSSL/wolfssl.git C:\Users\<you>\source\repos\wolfssl
cd C:\Users\<you>\source\repos\wolfssl
git checkout v5.9.0-stable
```

### 2. Create user_settings.h

Place the following file at `<wolfssl-repo>\wolfssl\user_settings.h`:

```c
#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* TLS 1.3 core */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define NO_OLD_TLS

/* Key exchange */
#define HAVE_DH
#define HAVE_FFDHE_2048

/* ECC support */
#define HAVE_ECC
#define HAVE_ECC256
#define ECC_TIMING_RESISTANT
#define HAVE_ECC_SIGN
#define HAVE_ECC_VERIFY
#define HAVE_ECC_KEY_IMPORT
#define HAVE_ECC_KEY_EXPORT
#define ECC_SHAMIR
#define ECC_ENCODING_RAW
#define HAVE_ECC_CDH
#define FP_ECC
#define FP_MAX_BITS 4096

/* RSA support */
#define WC_RSA_BLINDING
#define WC_RSA_PSS

/* Symmetric ciphers */
#define HAVE_AESGCM
#define HAVE_AEAD
#define HAVE_CHACHA
#define HAVE_POLY1305
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT

/* Hashing */
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* Key derivation */
#define HAVE_HKDF

/* TLS 1.3 internals */
#define HAVE_SESSION_TICKET
#define WOLFSSL_TICKET_HAVE_ID
#define HAVE_ENCRYPT_THEN_MAC

/* Certificate and ASN support */
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_PEM
#define WOLFSSL_CERT_GEN
#define OPENSSL_EXTRA

/* Error code compatibility */
#define WOLFSSL_ERROR_CODE_OPENSSL

/* Filesystem support */
#undef NO_FILESYSTEM

/* Windows socket support */
#define USE_WINDOWS_API

/* Post-quantum hybrid key exchange */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_WC_ML_KEM_768
#define WOLFSSL_EXPERIMENTAL_SETTINGS

#endif
```

### 3. Build wolfSSL

1. Open `wolfssl64.sln` (or `wolfssl.sln`) in Visual Studio 2022. Accept any retargeting prompts.
2. In the **wolfssl** project properties, go to **C/C++ → Preprocessor → Preprocessor Definitions** and add `WOLFSSL_USER_SETTINGS` (keep any existing defines).
3. If wolfSSL cannot find `user_settings.h`, edit `wolfssl/wolfcrypt/settings.h` and change the `#include "user_settings.h"` line to use an absolute path:
   ```c
   #include "C:/Users/<you>/source/repos/wolfssl/wolfssl/user_settings.h"
   ```
4. **Add the ML-KEM source files** to the wolfssl project. Right-click Source Files → Add → Existing Item, then navigate to `wolfcrypt/src/` and add:
   - `wc_mlkem.c`
   - `wc_mlkem_poly.c`
5. **Add the SHA-3 source file** if not already present. Check for `sha3.c` in the project; if missing, add it from `wolfcrypt/src/sha3.c`.
6. Build the **wolfssl** project only (right-click → Build). Note the output path of `wolfssl.lib`.

### 4. Generate Test Certificates

Open Git Bash and run from this repo's root:

```bash
mkdir -p certs && cd certs

openssl ecparam -genkey -name prime256v1 -out ca-key.pem
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 365 -subj "/CN=Test CA"
openssl ecparam -genkey -name prime256v1 -out server-key.pem
openssl req -new -key server-key.pem -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 365
```

Note: The certificates use classical ECC for authentication. The post-quantum protection applies to the key exchange only, which is the standard hybrid deployment model.

### 5. Create the Visual Studio Solution

1. Open Visual Studio → File → New → Project → **Empty Project**.
2. Name it `tls13-hybrid-server`. Set the solution name to `tls13-hybrid`.
3. Right-click the Solution → Add → New Project → **Empty Project**, name it `tls13-hybrid-client`.
4. Add source files: `server.c` and `common.h` to the server project, `client.c` and `common.h` to the client project.

### 6. Configure Both Projects

Set these properties for **both** projects. Use **All Configurations / All Platforms** in the dropdowns.

| Setting | Value |
|---------|-------|
| C/C++ → General → Additional Include Directories | `C:\Users\<you>\source\repos\wolfssl;C:\Users\<you>\source\repos\wolfssl\wolfssl` |
| C/C++ → Preprocessor → Preprocessor Definitions | `WOLFSSL_USER_SETTINGS;%(PreprocessorDefinitions)` |
| C/C++ → Advanced → Compile As | Compile as C Code (/TC) |
| Linker → General → Additional Library Directories | `C:\Users\<you>\source\repos\wolfssl\Debug\x64` |
| Linker → Input → Additional Dependencies | `wolfssl.lib;ws2_32.lib;advapi32.lib;%(AdditionalDependencies)` |
| Debugging → Working Directory | Set to whichever directory contains your `certs/` folder |

### 7. Build and Run

1. Build both projects.
2. Run the server first: right-click `tls13-hybrid-server` → Set as Startup Project → Ctrl+F5.
3. Run the client: right-click `tls13-hybrid-client` → Set as Startup Project → Ctrl+F5.

Expected output:
```
TLS 1.3 handshake successful!
Cipher suite: TLS_AES_256_GCM_SHA384
Key Exchange: SecP256r1MLKEM768
```

## Differences from Classical Implementation

The hybrid implementation differs from the classical version in three ways:

1. **user_settings.h** includes additional defines for ML-KEM and SHA-3 support.
2. **wolfSSL build** requires adding `wc_mlkem.c`, `wc_mlkem_poly.c`, and `sha3.c` to the project.
3. **Server and client code** include a `wolfSSL_CTX_set_groups` call to request the `WOLFSSL_SECP256R1MLKEM768` hybrid key exchange group.

The certificate setup, symmetric encryption, and application-layer message exchange are identical.

## Portable Release Build

To create standalone executables that run on any 64-bit Windows machine:

1. Switch both projects to **Release** configuration.
2. Rebuild wolfSSL in Release mode.
3. Set **C/C++ → Code Generation → Runtime Library** to **Multi-threaded (/MT)** in both projects.
4. Rebuild. The resulting `.exe` files only need the `certs/` folder alongside them.

## Project Structure

```
wolfssl-tls13-hybrid/
├── certs/
│   ├── ca-cert.pem
│   ├── ca-key.pem
│   ├── server-cert.pem
│   └── server-key.pem
├── common.h
├── server.c
├── client.c
├── .gitignore
└── README.md
```

## Troubleshooting

**"WOLFSSL_SECP256R1MLKEM768 is undefined"** — wolfSSL needs `WOLFSSL_HAVE_MLKEM` and `WOLFSSL_WC_MLKEM` in `user_settings.h`, and the ML-KEM source files must be added to the wolfSSL VS project manually.

**"Failed to set hybrid KEM group, error: -173"** — The wolfSSL library was not compiled with ML-KEM support. Ensure `wc_mlkem.c` and `wc_mlkem_poly.c` are in the wolfSSL project, clean and rebuild wolfSSL, then rebuild your projects.

**"wc_Sha3 not found"** — Add `WOLFSSL_SHA3`, `WOLFSSL_SHAKE128`, and `WOLFSSL_SHAKE256` to `user_settings.h` and ensure `sha3.c` is in the wolfSSL project.

**"WC_RSA_PSS is required for TLS 1.3 with RSA"** — Add `WC_RSA_PSS` to `user_settings.h`.
