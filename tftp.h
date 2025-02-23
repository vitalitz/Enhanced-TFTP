#ifndef TFTP_H
#define TFTP_H

// **TFTP Standard Opcodes (RFC 1350)**
#define OP_RRQ          	1  // Read Request
#define OP_WRQ          	2  // Write Request
#define OP_DATA         	3  // Data Packet
#define OP_ACK          	4  // Acknowledgment
#define OP_ERROR        	5  // Error

// **TFTP Extended and Custom Opcodes**
#define OP_OACK         	6   // Option Acknowledgment (RFC 2347)
#define OP_MD5_VERIFY   	7   // Client sends MD5 for verification
#define OP_MD5_REQUEST  	8   // Client requests MD5 from server
#define OP_ENC_RRQ      	9   // Encrypted Read Request
#define OP_ENC_WRQ      	10  // Encrypted Write Request
#define OP_DELETE			11  // Custom TFTP DELETE request
#define OP_BUF_SIZE_SYNC	12  // Buffer Size Synchronization Request

// **Verbosity Levels**
#define VERB_ALWAYS				0	// Always log messages
#define VERB_NORMAL				1	// Normal logging
#define VERB_VERBOSE			2	// Detailed logging
#define VERB_DEBUG				3	// Debug-level logging

// **TFTP Error Codes**
#define ERR_UNDEFINED			0	// Not defined, see error message
#define ERR_FILE_NOT_FOUND		1	// File not found
#define ERR_ACCESS_VIOLATION	2	// Access violation
#define ERR_DISK_FULL			3	// Disk full or allocation exceeded
#define ERR_ILLEGAL_OP			4	// Illegal TFTP operation
#define ERR_UNKNOWN_TID			5	// Unknown transfer ID
#define ERR_FILE_EXISTS			6	// File already exists
#define ERR_NO_SUCH_USER		7	// No such user
#define ERR_MD5_MISMATCH		8	// MD5 mismatch
#define ERR_ENCRYPTION_FAIL		9	// Encryption/Decryption failure

#endif /* TFTP_H */
