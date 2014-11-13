/*
 * sig_client.h
 * Author: Alec Guertin
 * CS161-FA14 Project 1
 *
 * This file includes prototypes for functions used in sig_client.c.
 * The autograder will test these functions for correctness, so be
 * sure to follow the instructions on return values closely.
 */

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <gmp.h>
#include "sha256.h"
#include "aes.h"
#include "handshake.h"

void mpz_get_ascii(char *output_str, mpz_t input);
char *hex_to_str(char *data, int data_len);
int get_cert_exponent(mpz_t result, char *cert);
int get_cert_modulus(mpz_t result, char *cert);

void decrypt_cert(mpz_t decrypted_cert, cert_message *cert, mpz_t key_exp, mpz_t key_mod);
void decrypt_verify_master_secret(mpz_t decrypted_ms, ps_msg *ms_ver, mpz_t key_exp, mpz_t key_mod);
void compute_master_secret(int pms, int client_random, int server_random, unsigned char *master_secret);
int send_tls_message(int socketno, void *msg, int msg_len);
int receive_tls_message(int socketno, void *msg, int msg_len, int msg_type);
