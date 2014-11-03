/*
 * DO NOT MODIFY THIS FILE!!!
 *
 * handshake.h
 *
 * Author: Alec Guertin
 * University of California, Berkeley
 * CS 161 - Intro to Computer Security
 * Fall 2014 Semester
 * Project 1
 *
 * This file includes definitions of constants and
 * types for the handshake protocol. Read carefully
 * for tips on implementing the protocol.
 */

/* Error codes. */
#define ERR_OK 0
#define ERR_FAILURE 1

/* Networking and crypto constants. */
#define HANDSHAKE_PORT 6970
#define MAX_RECEIVE_BYTES 1500
#define RSA_MAX_LEN 1200
#define HEX_BASE 16
#define BYTE_SIZE 8
#define AES_BLOCK_SIZE 16
#define SHA_BLOCK_SIZE 16

/* Macros defining the sizes of various messages for use in reading and sending messages. */
#define INT_SIZE sizeof(int)
#define HELLO_MSG_SIZE 3*INT_SIZE
#define CERT_MSG_SIZE INT_SIZE + RSA_MAX_LEN
#define PS_MSG_SIZE INT_SIZE + RSA_MAX_LEN
#define TLS_MSG_SIZE MAX_RECEIVE_BYTES

/* TLS message types for hello messages. For detailed descriptions, see spec. */
#define ERROR_MESSAGE 0x0
#define CLIENT_HELLO 0x1
#define SERVER_HELLO 0x2
#define CLIENT_CERTIFICATE 0x3
#define SERVER_CERTIFICATE 0x4
#define PREMASTER_SECRET 0x5
#define VERIFY_MASTER_SECRET 0x6
#define ENCRYPTED_MESSAGE 0x7

/* Cipher suite constants for hello messages. */
#define TLS_RSA_WITH_AES_128_ECB_SHA256 0x3C

/* Public key for trusted certificate authority (CA). */
#define CA_EXPONENT "0x10001"

#define CA_MODULUS "0x00bb500eb136a10c6ede5ff77270d6e5f8dbf0b92dd7fe1a5df274503cb7435b373442d5a70a68bdfe45131667ffa3d62cd387274c607690d045682ba50abb2f4459bbdb3677eb485fd94955f7e0a3c8bfc5781be004aa80dcfe5deea7eafb2f0dbbda2e0a490f2777dc5a754db62777cbdcfd452396fd0c3c37ee6f5cf96b9ba2eb9274c7f7798cb50c3f778ff1d683407949443e0150c208f078b8ecfa6b93c1203cc0b6194caf1a724477f81b3aae1cf62bde266ffe19d3f77033d5cd7a90ea442dab4f97631da42c474dad2379314403419fd7431db844ef57f3660375563d5ef85dc404f20d473c66b6f47b296a304506b76d9acb74f37368c59d3485ddd2b3effa7e29bcd0faf3cdf294b70d1e2b312b7493a99a22fbba5e1dd4f89bb10e75c53b29d9a1075153717bf52b3b44b9cbc06c45afc5b3d029294df2e73579a8e64898aeb8bd89ea4ba5a3a8c507ddc09f38711c6132386ca5497199f01a092bb3e323b841b5ed23eea239bd6c4fa738ec575a1051a38f2691b235343ff9f2740498cd391aaccc03323a3ff06d4406c2eb88ff73392dd0f23c28f0f7f60c87c0c40a74fd4c28fdc352c3b506acca9fb1295c0117ddec5eb8d7304466855e660cb42f29d7be6eff5d443544fb67f3ff1e8340369cc4389e159a11e01b81dd4b4faea192bfdcbf87afbe7a0400f954c3da8380ee664c4be89ee476ee318d557095"

/* Used for CLIENT_HELLO and SERVER_HELLO. */
typedef struct {
  int type;
  int random;
  int cipher_suite;
} hello_message;

/* Used for CLIENT_CERTIFICATE and SERVER_CERTIFICATE. */
typedef struct {
  int type;
  char cert[RSA_MAX_LEN];
} cert_message;

/* Used for PREMASTER_SECRET and VERIFY_MASTER_SECRET. */
typedef struct {
  int type;
  char ps[RSA_MAX_LEN];
} ps_msg;

/* Used for ERROR_MESSAGE and ENCRYPTED_MESSAGE.  */
typedef struct {
  int type;
  char msg[MAX_RECEIVE_BYTES-sizeof(int)];
} tls_msg;
