# Enhanced TFTP Server & Client

This project implements an enhanced TFTP (Trivial File Transfer Protocol) server and client written in C. It extends the standard TFTP protocol with additional features such as AES encryption, MD5 integrity verification, dynamic buffer size negotiation, and file deletion, along with robust logging and ephemeral port management.

## Features

- **Standard TFTP Operations:**

  - Supports Read Requests (RRQ) for file downloads, Write Requests (WRQ) for file uploads, and DELETE operations to remove files from the server.

- **AES Encryption:**

  - Enables secure file transfers by encrypting data using AES when a key file is provided.

- **MD5 Integrity Verification:**

  - Provides MD5 hash computation and verification to ensure file integrity after transfers. The client can request and compare MD5 hashes from the server.

- **Dynamic Buffer Size Negotiation:**

  - Clients can negotiate a custom buffer size (between 512 and 8192 bytes) with the server to optimize performance under varying network conditions.

- **Ephemeral Port Management:**

  - Uses ephemeral ports for data transfers to separate control and data channels, enhancing reliability and flexibility.

- **Robust Logging:**

  - Configurable verbosity levels allow detailed logging of operations. Build logs are maintained in the `build/build.log` file.

- **Command-Line Configuration:**

  - Both client and server accept various command-line options to specify settings such as server IP, port, file path, operation mode (PUT, GET, DELETE), buffer size, MD5 verification, and AES key file.

## Compilation & Installation

### Prerequisites

Ensure you have the following installed:

- **GCC Compiler** (`gcc`)
- **OpenSSL Libraries** (`libssl-dev` for Linux)
- **Make**

### Build Instructions

To compile both the client and server, run:

```sh
make
```

This will create the executables in the `build/` directory.

If you need to clean previous builds, run:

```sh
make clean
```

## Usage

### Server

To start the server with default settings:

```sh
./build/server
```

To specify a custom port:

```sh
./build/server --port 1069
```

### Client

#### Download a file (GET)

```sh
./build/client --server 192.168.1.10 --get example.txt
```

#### Upload a file (PUT)

```sh
./build/client --server 192.168.1.10 --put example.txt
```

#### Delete a file from the server

```sh
./build/client --server 192.168.1.10 --delete example.txt
```

#### Enable MD5 Verification

```sh
./build/client --server 192.168.1.10 --get example.txt --md5
```

#### Enable AES Encryption

```sh
./build/client --server 192.168.1.10 --put example.txt --keyfile mykey.aes
```

## Project Structure

```
├── client.c              # TFTP client implementation
├── server.c              # TFTP server implementation
├── md5_utils.c           # MD5 checksum computation utilities
├── md5_utils.h           # MD5 checksum function declarations
├── crypto_utils.c        # AES encryption/decryption utilities
├── crypto_utils.h        # AES encryption function declarations
├── tftp.h                # TFTP protocol definitions and opcodes
├── Makefile              # Build system configuration
├── apply_setcap.sh       # Script to set capabilities
├── README.md             # Project documentation
└── build/                # Compiled binaries & log files
```

## License

This project is licensed under the MIT License.

## Author

Vitali Tziganov
