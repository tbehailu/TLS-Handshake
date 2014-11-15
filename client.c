/*
* sig_client.c
*
* Author: Alec Guertin
* University of California, Berkeley
* CS 161 - Computer Security
* Fall 2014 Semester
* Project 1
*/

#include "client.h"

/* The file descriptor for the socket connected to the server. */
static int sockfd;

static void perform_rsa(mpz_t result, mpz_t message, mpz_t d, mpz_t n);
static int hex_to_ascii(char a, char b);
static int hex_to_int(char a);
static void usage();
static void kill_handler(int signum);
static int random_int();
static void cleanup();
void printVariable(char *input);
void printCertificate(mpz_t result);
void printCharArray(char *arr);
void printUnsignedCharArray(unsigned char *arr);

/* Helper function, assigns into to char array. */
static void assign (unsigned char *pass, uint32_t val);

int main(int argc, char **argv) {

    /* Various set up code - declare vars, etc. */
    int err, option_index, c, clientlen, counter;
    unsigned char rcv_plaintext[AES_BLOCK_SIZE];
    unsigned char rcv_ciphertext[AES_BLOCK_SIZE];
    unsigned char send_plaintext[AES_BLOCK_SIZE];
    unsigned char send_ciphertext[AES_BLOCK_SIZE];
    aes_context enc_ctx, dec_ctx;

    /* Set up IP vars and messages. */
    in_addr_t ip_addr;
    struct sockaddr_in server_addr;
    FILE *c_file, *d_file, *m_file;
    ssize_t read_size, write_size;
    struct sockaddr_in client_addr;
    tls_msg err_msg, send_msg, rcv_msg;
    mpz_t client_exp, client_mod;
    fd_set readfds;
    struct timeval tv;

    c_file = d_file = m_file = NULL;

    mpz_init(client_exp);
    mpz_init(client_mod);

    /*
    * This section is networking code that you don't need to worry about.
    * Look further down in the function for your part.
    */

    memset(&ip_addr, 0, sizeof(in_addr_t));

    option_index = 0;
    err = 0;

    /* This is a neat CLI args parser. */
    static struct option long_options[] = {
        {"ip", required_argument, 0, 'i'},
        {"cert", required_argument, 0, 'c'},
        {"exponent", required_argument, 0, 'd'},
        {"modulus", required_argument, 0, 'm'},
        {0, 0, 0, 0},
    };

    while (1) { // Lol.
        c = getopt_long(argc, argv, "c:i:d:m:", long_options, &option_index);
        if (c < 0) {
            break;
        }
        switch(c) {
            case 0:
            usage();
            break;
            case 'c':
            c_file = fopen(optarg, "r");
            if (c_file == NULL) {
                perror("Certificate file error");
                exit(1);
            }
            break;
            case 'd':
            d_file = fopen(optarg, "r");
            if (d_file == NULL) {
                perror("Exponent file error");
                exit(1);
            }
            break;
            case 'i':
            ip_addr = inet_addr(optarg);
            break;
            case 'm':
            m_file = fopen(optarg, "r");
            if (m_file == NULL) {
                perror("Modulus file error");
                exit(1);
            }
            break;
            case '?':
            usage();
            break;
            default:
            usage();
            break;
        }
    }

    if (d_file == NULL || c_file == NULL || m_file == NULL) {
        usage();
    }
    if (argc != 9) {
        usage();
    }

    mpz_inp_str(client_exp, d_file, 0);
    mpz_inp_str(client_mod, m_file, 0);

    signal(SIGTERM, kill_handler); // TODO - find out what this does.

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Could not open socket");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = ip_addr;
    server_addr.sin_port = htons(HANDSHAKE_PORT);
    err = connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
    if (err < 0) {
        perror("Could not bind socket");
        cleanup();
    }

    // YOUR CODE HERE
    // IMPLEMENT THE TLS HANDSHAKE
    int exit_code; // used for catching errors.

    /* NOTE - THIS CODE IS NOT COMPLETE YET. */
    /* ---------  1. send Client hello ---------*/
    hello_message c_hello;
    c_hello.type = CLIENT_HELLO;
    c_hello.random = random_int();

    // print statement for write-up #2
    // printf("random int = %d\n",c_hello.random);

    c_hello.cipher_suite = TLS_RSA_WITH_AES_128_ECB_SHA256;
    exit_code = send_tls_message(sockfd, &c_hello, HELLO_MSG_SIZE);
    if (exit_code < 0) {
        printf("caught error! TODO - quit here.");
    }


    /* ---------- 2. receive Server hello --------*/

    hello_message s_hello;
    exit_code = receive_tls_message(sockfd, &s_hello, HELLO_MSG_SIZE, SERVER_HELLO);
    if (exit_code < 0) {
        printf("caught error! TODO - quit here.");
    }
    int server_random = s_hello.random;


    /* --------- 3. send client cert ----------*/
    cert_message c_cert;
    c_cert.type = CLIENT_CERTIFICATE;

    /****** TODO: Double check *******/

    // read c_file into buffer

    // char buffer[CERT_MSG_SIZE];
    // fread(buffer, CERT_MSG_SIZE, 1, c_file);
    // memcpy(c_cert.cert, buffer, RSA_MAX_LEN);

    memset(c_cert.cert, 0, RSA_MAX_LEN); // set the message to zero before assigning
    fgets(c_cert.cert, RSA_MAX_LEN, c_file); 
    printf("c_file contents: %s\n", hex_to_str(c_cert.cert, RSA_MAX_LEN));
    printCharArray(hex_to_str(c_cert.cert, RSA_MAX_LEN));
    
    //memcpy(c_cert.cert, /* client_certificate goes here - use c_file, just read file. Might need to use gmp - string to mpz_t*/, RSA_MAX_LEN);
    
    
    exit_code = send_tls_message(sockfd, &c_cert, CERT_MSG_SIZE);
    if (exit_code < 0) {
        printf("Error: Did not send client certificate correctly.");
    }

    /* ----------  4. receive server cert ----------*/
    cert_message s_cert;
    // s_cert.type = SERVER_CERTIFICATE;
    exit_code = receive_tls_message(sockfd, &s_cert, CERT_MSG_SIZE, SERVER_CERTIFICATE);
    if (exit_code < 0 || exit_code == ERR_FAILURE) {
        printf("Error: Did not receive server certificate correctly.\n");
        printf("exit_code = %d\n", exit_code);
        printCharArray(s_cert.cert);

    }

    // TODO: find out how to get the hex part from CA_EXPONENT and CA_MODULUS so I don't have to hard code it in anymore
    /* -------- 4.1 decrypt server certificate and extract server public key -----*/
    // Get CA mod and exp
    mpz_t ca_exp;
    mpz_init(ca_exp);
    mpz_set_str(ca_exp, CA_EXPONENT,0); // 0x10001 = 65537
    mpz_t ca_mod;
    mpz_init(ca_mod);
    mpz_set_str(ca_mod, CA_MODULUS, 0);

    printf("ca_exp: ");
    mpz_out_str(stdout, 10, ca_exp);
    printf("\n");
    // printf("ca_mod: ");
    // mpz_out_str(stdout, 10, ca_mod);
    // printf("\n");

    // decrypt server
    mpz_t decrypted_cert;
    mpz_init(decrypted_cert);
    decrypt_cert(decrypted_cert, &s_cert, ca_exp, ca_mod);
    
    // hex_to_str(CA_MODULUS, RSA_MAX_LEN);

    // printf("decrypted_cert: ");
    // mpz_out_str(stdout, 10, decrypted_cert);
    // printf("\n");

    // printVariable(mpz_get_str(NULL, HEX_BASE, decrypted_cert));
    // mpz_t test;
    // mpz_init_set_str(test, mpz_get_str(NULL, HEX_BASE, decrypted_cert), 16);
    // mpz_out_str(stdout,10,test);
    // printf("\n");

    // save decrypted_cert into a string
    // char *server_cert_string = mpz_get_str(NULL, HEX_BASE, decrypted_cert);
    char server_cert_string[CERT_MSG_SIZE];
    mpz_get_ascii(server_cert_string, decrypted_cert);

    // extract server exponent
    mpz_t server_exponent;
    mpz_init(server_exponent);
    // printf("server_cert_string: %s, length: %d\n", server_cert_string, strlen(server_cert_string));
    get_cert_exponent(server_exponent, server_cert_string); // gives seg fault

    // printf("we got cert exponent!\n");

    // extract server mod
    mpz_t server_mod;
    mpz_init(server_mod);
    get_cert_modulus(server_mod, server_cert_string);

    // printf("we got cert mod!\n");

    /* -----  5. Compute premaster secret, send it to server, encrypted with server public key --------*/

    // prepare data structures
    ps_msg psm;
    psm.type = PREMASTER_SECRET;
    int ps = random_int();

    mpz_t ps_mpz;
    mpz_init_set_si(ps_mpz, ps);
    // start encryption
    mpz_t encrypted_premaster;
    mpz_init(encrypted_premaster);
    perform_rsa(encrypted_premaster, ps_mpz, server_exponent, server_mod); // encrypt with server key

    // printf("encrypted_premaster = %s\n", hex_to_str(encrypted_premaster,RSA_MAX_LEN));

    printf("we encrypted the premaster!\n");

    char* encrypted_premaster_string = mpz_get_str(NULL, HEX_BASE, encrypted_premaster);
    // char encrypted_premaster_string[CERT_MSG_SIZE];
    // mpz_get_ascii(encrypted_premaster_string, encrypted_premaster);
    printf("encrypted_premaster: ");
    printCertificate(ps_mpz);
    printf("encrypted_premaster_string: ");
    printCharArray(encrypted_premaster_string);

    /*** TODO: Double check how premaster is being set ****/
    memset(psm.ps, 0, RSA_MAX_LEN); // set the message to zero before assigning
    memcpy(psm.ps, encrypted_premaster_string, RSA_MAX_LEN); // copy to message
    printCharArray(psm.ps);

    // send the message
    exit_code = send_tls_message(sockfd, &psm, PS_MSG_SIZE);
    if (exit_code < 0) {
        printf("caught error! TODO - quit here.");
    }

    printf("we have sent the premaster secret!\n");

    /* --------  6. compute the local master secret -------*/

    unsigned char local_master[RSA_MAX_LEN];
    compute_master_secret(ps, c_hello.random, s_hello.random, local_master);

    // printf("c_hello.random: %d, s_hello.random: %d\n", c_hello.random, s_hello.random);

    printf("computed master secret!\n");
    printUnsignedCharArray(local_master);

    // 6.1 and now receive the server master, confirm it's the same
    ps_msg psm_response;
    // psm_response.type = malloc(sizeof(int));
    exit_code = receive_tls_message(sockfd, &psm_response, TLS_MSG_SIZE, VERIFY_MASTER_SECRET);
    if (exit_code < 0 || exit_code == ERR_FAILURE) {
        printf("Error: Did not receive server master correctly.\n");
        // return ERR_FAILURE;
    }

    printf("received server master; exit_code: %d\n", exit_code);
    // printf("psm_response: %d, s_hello.random: %d\n", *((int *) psm_response), s_hello.random);

    mpz_t server_premaster;
    mpz_init(server_exponent);
    decrypt_verify_master_secret(server_premaster, &psm_response, client_exp, client_mod);


    // TODO: check that str(server_premaster) == local_master
    printf("server_premaster = ");
    mpz_out_str(stdout, 16, server_premaster);
    printf("\n");
    printf("local_master = ");
    printUnsignedCharArray(local_master);
    printCertificate(server_premaster);
    printf("\n");



    /*
    * START ENCRYPTED MESSAGES
    */

    memset(send_plaintext, 0, AES_BLOCK_SIZE);
    memset(send_ciphertext, 0, AES_BLOCK_SIZE);
    memset(rcv_plaintext, 0, AES_BLOCK_SIZE);
    memset(rcv_ciphertext, 0, AES_BLOCK_SIZE);

    memset(&rcv_msg, 0, TLS_MSG_SIZE);

    aes_init(&enc_ctx);
    aes_init(&dec_ctx);

    // YOUR CODE HERE
    // SET AES KEYS - to master_secret

    /* NOT DONE! */
    /*
    if (aes_setkey_enc(&enc_ctx, uchar* local_master, 128)) {
        printf("Error setting key.\n");
    }

    if (aes_setkey_enc(&dec_ctx, uchar* local_master, 128)) {
        printf("Error setting key.\n");
    }
    */
    if (aes_setkey_enc(&enc_ctx, local_master, 128)) {
        printf("Error setting encryption key.\n");
    }

    if (aes_setkey_enc(&dec_ctx, local_master, 128)) {
        printf("Error setting decryption key.\n");
    }

    printf("made it to the end of handshake!\n");





    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    /* Send and receive data. */
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sockfd, &readfds);
        tv.tv_sec = 2;
        tv.tv_usec = 10;

        select(sockfd+1, &readfds, NULL, NULL, &tv);
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            counter = 0;
            memset(&send_msg, 0, TLS_MSG_SIZE);
            send_msg.type = ENCRYPTED_MESSAGE;
            memset(send_plaintext, 0, AES_BLOCK_SIZE);
            read_size = read(STDIN_FILENO, send_plaintext, AES_BLOCK_SIZE);
            while (read_size > 0 && counter + AES_BLOCK_SIZE < TLS_MSG_SIZE - INT_SIZE) {
                if (read_size > 0) {
                    err = aes_crypt_ecb(&enc_ctx, AES_ENCRYPT, send_plaintext, send_ciphertext);
                    memcpy(send_msg.msg + counter, send_ciphertext, AES_BLOCK_SIZE);
                    counter += AES_BLOCK_SIZE;
                }
                memset(send_plaintext, 0, AES_BLOCK_SIZE);
                read_size = read(STDIN_FILENO, send_plaintext, AES_BLOCK_SIZE);
            }
            write_size = write(sockfd, &send_msg, INT_SIZE+counter+AES_BLOCK_SIZE);
            if (write_size < 0) {
                perror("Could not write to socket");
                cleanup();
            }
        } else if (FD_ISSET(sockfd, &readfds)) {
            memset(&rcv_msg, 0, TLS_MSG_SIZE);
            memset(rcv_ciphertext, 0, AES_BLOCK_SIZE);
            read_size = read(sockfd, &rcv_msg, TLS_MSG_SIZE);
            if (read_size > 0) {
                if (rcv_msg.type != ENCRYPTED_MESSAGE) {
                    goto out;
                }
                memcpy(rcv_ciphertext, rcv_msg.msg, AES_BLOCK_SIZE);
                counter = 0;
                while (counter < read_size - INT_SIZE - AES_BLOCK_SIZE) {
                    aes_crypt_ecb(&dec_ctx, AES_DECRYPT, rcv_ciphertext, rcv_plaintext);
                    printf("%s", rcv_plaintext);
                    counter += AES_BLOCK_SIZE;
                    memcpy(rcv_ciphertext, rcv_msg.msg+counter, AES_BLOCK_SIZE);
                }
            }
        }

    }

    out:
    close(sockfd);
    return 0;
}

/*
* \brief                  Decrypts the certificate in the message cert.
*
* \param decrypted_cert   This mpz_t stores the final value of the binary
*                         for the decrypted certificate. Write the end
*                         result here.
* \param cert             The message containing the encrypted certificate.
* \param key_exp          The exponent of the public key for decrypting
*                         the certificate.
* \param key_mod          The modulus of the public key for decrypting
*                         the certificate.
*/
void
decrypt_cert(mpz_t decrypted_cert, cert_message *cert, mpz_t key_exp, mpz_t key_mod)
{
    // printf("decrypting a certificate\n");

    mpz_t mpz_cert;
    mpz_init(mpz_cert);
    mpz_set_str(mpz_cert, hex_to_str(cert->cert,RSA_MAX_LEN), 0); // note, leading '0x' may cause issues.t
    perform_rsa(decrypted_cert, mpz_cert, key_exp, key_mod);
    printCertificate(decrypted_cert);

    /*
    // debug
    char* result_str = mpz_get_str(NULL, 16, decrypted_cert);
    int i = 0;
    while(result_str[i] != '\0') {
        printf("%c", hex_to_ascii(result_str[i], result_str[i+1]));
        i+=2;
    }
    printf("done decrypting a certificate\n");
    // end debug
    */
}

/*
* \brief                  Decrypts the master secret in the message ms_ver.
*
* \param decrypted_ms     This mpz_t stores the final value of the binary
*                         for the decrypted master secret. Write the end
*                         result here.
* \param ms_ver           The message containing the encrypted master secret.
* \param key_exp          The exponent of the public key for decrypting
*                         the master secret.
* \param key_mod          The modulus of the public key for decrypting
*                         the master secret.
*/
void
decrypt_verify_master_secret(mpz_t decrypted_ms, ps_msg *ms_ver, mpz_t key_exp, mpz_t key_mod)
{
    /* This code is not done. Be careful! */
    mpz_t ps;
    mpz_init(ps);
    // mpz_set_str(ca_exp, CA_EXPONENT,0);
    // mpz_set_str(mpz_cert, hex_to_str(cert->cert,RSA_MAX_LEN), 0);
    mpz_set_str(ps, hex_to_str(ms_ver->ps,RSA_MAX_LEN), 0);
    printf("decrypting the master secret..\n");
    // perform the decryption
    perform_rsa(decrypted_ms, ps, key_exp, key_mod);
    printCertificate(decrypted_ms);

    // done?
}

/*
* \brief                  Computes the master secret.
*
* \param ps               The premaster secret.
* \param client_random    The random value from the client hello.
* \param server_random    The random value from the server hello.
* \param master_secret    A pointer to the final value of the master secret.
*                         Write the end result here.
*/
void
compute_master_secret(int ps, int client_random, int server_random, unsigned char *master_secret)
{
    // IMPORTANT - DEBUG THIS FUNCTION! It is untested and is likely buggy.
    printf("computing the master secret..\n");
    // ps
    unsigned char ps_array[8];
    assign(ps_array, ps); // use assign from gentable. remember it's size 8.
    

    // client secret
    unsigned char cli_array[8];
    assign(cli_array, client_random); // use assign from gentable. remember it's size 8.

    // server secret
    unsigned char ser_array[8];
    assign(ser_array, server_random); // use assign from gentable. remember it's size 8.


    // unsigned char *hash_data = (unsigned char *)calloc(32, sizeof(unsigned char));
    // hash_data[0] = ps_array;
    // for (int i = 0; i < 8; i++){
    //     assign(hash_data, (int)ps_array[i]);
    // }
    // for (int i = 0; i < 8; i++){
    //     assign(hash_data+8, (int)cli_array[i]);
    // }
    // for (int i = 0; i < 8; i++){
    //     assign(hash_data+16, (int)ser_array[i]);
    // }
    // for (int i = 0; i < 8; i++){
    //     assign(hash_data+24, (int)ps_array[i]);
    // }
    int arr[4] = {ps, client_random, server_random, ps}; 
    unsigned char *hash_data = malloc(16);
    // hash_data = (unsigned char *) arr;
    // hash_data << ps_array;
    printUnsignedCharArray(hash_data);

    // add to hash
    // Master secret = H(PS||clienthello.random||serverhello.random||PS)

    // void sha256_update(SHA256_CTX *ctx, uchar data[], uint len)


    
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, ps_array, 8);
    sha256_update(&ctx, cli_array, 8);
    sha256_update(&ctx, ser_array, 8);
    sha256_update(&ctx, ps_array, 8);
    sha256_final(&ctx, master_secret);

    // free(hash_data);
}

/*
* \brief                  Sends a message to the connected server.
*                         Returns an error code.
*
* \param socketno         A file descriptor for the socket to send
*                         the message on.
* \param msg              A pointer to the message to send.
* \param msg_len          The length of the message in bytes.
*/
int
send_tls_message(int socketno, void *msg, int msg_len)
{
    int write_result = write(socketno, msg, msg_len);
    if (write_result == -1) {
        printf("Error sending TLS message. Error code: %d \n", errno);
    }
    if (write_result != msg_len) {
        printf("Warning: message was not fully written!\n");
        write_result = -1; // set return code to -1.
    }
    return write_result;
}

/*
* \brief                  Receieves a message from the connected server.
*                         Returns an error code.
*
* \param socketno         A file descriptor for the socket to receive
*                         the message on.
* \param msg              A pointer to where to store the received message.
* \param msg_len          The length of the message in bytes.
* \param msg_type         The expected type of the message to receive.
*/
int
receive_tls_message(int socketno, void *msg, int msg_len, int msg_type)
{
    // debugging print statements
    // void * to int reference: http://stackoverflow.com/questions/1640423/error-cast-from-void-to-int-loses-precision

    // printf("msg.type = %d, msg_type = %d\n", type_of_msg, msg_type);

    // TODO: Double-check
    int read_result = read(socketno, msg, msg_len);
    int type_of_msg = *((int *)msg);
    printf("read_result = %d, msg_len = %d\n", read_result, msg_len);
    printf("type_of_msg = %d, msg_type = %d\n", type_of_msg, msg_type);

    if (read_result != msg_len){ // if bytes read is not correct length or msg_type is error, return error
        return ERR_FAILURE;
    }

    if (type_of_msg == msg_type){
        return ERR_OK;
    }

    return ERR_FAILURE;

    // if (msg_type == CLIENT_HELLO){
    //     // return ERR_OK; ??
    // }

    // if (msg_type == SERVER_HELLO){
    //     // return ERR_OK;
    // }

    // if (msg_type == CLIENT_CERTIFICATE){
    //     // return ERR_OK;
    // }

    // if (msg_type == SERVER_CERTIFICATE){
    //     // cert_message* ret = (struct cert_message*) msg;
    //     // printf("ret->cert: %s\n", ret->cert);
    //     // return ERR_OK;
    // }

    // if (msg_type == PREMASTER_SECRET){
    //     // return ERR_OK;
    // }

    // if (msg_type == VERIFY_MASTER_SECRET){
    //     return ERR_OK;
    // }

    // if (msg_type == ENCRYPTED_MESSAGE){
    //     return ERR_OK;
    // }

    /*
    if (read_result == -1) {
        printf("Error sending TLS message. Error code: %d \n", errno);
    }
    if (read_result != msg_len) {
        printf("Warning: message was not fully read!\n");
        read_result = -1; // set error return code.
    }
    return read_result;
    */
}


/* Returns 1 if odd, zero if not. Used in perform_rsa. Note - staff solutions are more elegant. */
static int is_odd(mpz_t d) {
    mpz_t test;
    mpz_init(test);
    mpz_div_ui(test, d, 2);
    mpz_mul_ui(test, test, 2);
    int cmp = mpz_cmp(d, test) == 0 ? 0 : 1;
    mpz_clear(test);
    return cmp;
}

/*
* \brief                Encrypts/decrypts a message using the RSA algorithm.
*
* \param result         a field to populate with the result of your RSA calculation.
* \param message        the message to perform RSA on. (probably a cert in this case)
* \param e              the encryption key from the key_file passed in through the
*                       command-line arguments
* \param n              the modulus for RSA from the modulus_file passed in through
*                       the command-line arguments
*
* Fill in this function with your proj0 solution or see staff solutions.
*/


static void
perform_rsa(mpz_t result, mpz_t message, mpz_t e, mpz_t n)
{
 /*
    mpz_set_ui(result, 1ul);
    while (mpz_cmp_ui(e, 0ul) > 0) {
        if (is_odd(e)) {
            mpz_mul(result, result, message);
            mpz_mod(result, result, n);
        }
        mpz_mul(message,message,message);
        mpz_mod(message, message, n);
        mpz_div_ui(e, e, 2);
    }
*/
    /* Checking with staff solution to proj0 */
    int odd_num;

    mpz_set_str(result, "1", 10);
    odd_num = mpz_odd_p(e);
    while (mpz_cmp_ui(e, 0) > 0) {
    if (odd_num) {
      mpz_mul(result, result, message);
      mpz_mod(result, result, n);
      mpz_sub_ui(e, e, 1);
    }
    mpz_mul(message, message, message);
    mpz_mod(message, message, n);
    mpz_div_ui(e, e, 2);
    odd_num = mpz_odd_p(e);
  }
  // debugging..
  // printf("perform_rsa output: ");
  // mpz_out_str (stdout, 10, result);
  // printf("\n");
}


/* Returns a pseudo-random integer. */
static int
random_int()
{
  srand(time(NULL));
  return rand();
}

/*
 * \brief                 Returns ascii string from a number in mpz_t form.
 *
 * \param output_str      A pointer to the output string.
 * \param input           The number to convert to ascii.
 */
void
mpz_get_ascii(char *output_str, mpz_t input)
{
  int i,j;
  char *result_str;
  result_str = mpz_get_str(NULL, HEX_BASE, input);
  i = 0;
  j = 0;
  while (result_str[i] != '\0') {
    output_str[j] = hex_to_ascii(result_str[i], result_str[i+1]);
    j += 1;
    i += 2;
  }
}

/*
 * \brief                  Returns a pointer to a string containing the
 *                         characters representing the input hex value.
 *
 * \param data             The input hex value.
 * \param data_len         The length of the data in bytes.
 */
char
*hex_to_str(char *data, int data_len)
{
  int i;
  char *output_str = calloc(1+2*data_len, sizeof(char));
  for (i = 0; i < data_len; i += 1) {
    snprintf(output_str+2*i, 3, "%02X", (unsigned int) (data[i] & 0xFF));
  }
  return output_str;
}

/* Return the public key exponent given the decrypted certificate as string. */
int
get_cert_exponent(mpz_t result, char *cert)
{
  int err;
  char *srch, *srch2;
  char exponent[RSA_MAX_LEN/2];
  memset(exponent, 0, RSA_MAX_LEN/2);
  srch = strchr(cert, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, ':');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 2;
  srch2 = strchr(srch, '\n');
  if (srch2 == NULL) {
    return ERR_FAILURE;
  }
  strncpy(exponent, srch, srch2-srch);
  err = mpz_set_str(result, exponent, 0);
  if (err == -1) {
    return ERR_FAILURE;
  }
  return ERR_OK;
}

/* Return the public key modulus given the decrypted certificate as string. */
int
get_cert_modulus(mpz_t result, char *cert)
{
  int err;
  char *srch, *srch2;
  char modulus[RSA_MAX_LEN/2];
  memset(modulus, 0, RSA_MAX_LEN/2);
  srch = strchr(cert, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, ':');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 2;
  srch2 = strchr(srch, '\n');
  if (srch2 == NULL) {
    return ERR_FAILURE;
  }
  strncpy(modulus, srch, srch2-srch);
  err = mpz_set_str(result, modulus, 0);
  if (err == -1) {
    return ERR_FAILURE;
  }
  return ERR_OK;
}


/* Prints the usage string for this program and exits. */
static void
usage()
{
    printf("./client -i <server_ip_address> -c <certificate_file> -m <modulus_file> -d <exponent_file>\n");
    exit(1);
}

/* Catches the signal from C-c and closes connection with server. */
static void
kill_handler(int signum)
{
    if (signum == SIGTERM) {
        cleanup();
    }
}

/* Converts the two input hex characters into an ascii char. */
static int
hex_to_ascii(char a, char b)
{
    int high = hex_to_int(a) * 16;
    int low = hex_to_int(b);
    return high + low;
}

/* Converts a hex value into an int. */
static int
hex_to_int(char a)
{
    if (a >= 97) {
        a -= 32;
    }
    int first = a / 16 - 3;
    int second = a % 16;
    int result = first*10 + second;
    if (result > 9) {
        result -= 1;
    }
    return result;
}

/* Closes files and exits the program. */
static void
cleanup()
{
    close(sockfd);
    exit(1);
}


/* Assigns into to unsigned char array*/
void assign (unsigned char *arr, uint32_t val)
{
    int i;
    for (i = 7; i >= 0; i--) {
        arr[i] = (unsigned char) val & 0xFF;
        val >>= 8;
    }
}

void printVariable(char *input){
    int i;
    while(input[i] != '\0') {
        printf("%02x", input[i]);
        i+=1;
    }
    printf("\n");
}

void printCertificate(mpz_t result){
    char *result_str;
    result_str = mpz_get_str(NULL, 16, result);
    int i = 0;
    while(result_str[i] != '\0') {
        printf("%c", hex_to_ascii(result_str[i], result_str[i+1]));
        i+=2;
    }
    printf("\n");
}

void printCharArray(char *arr){
    int i = 0;
    while(arr[i] != '\0') {
        printf("%c", hex_to_ascii(arr[i], arr[i+1]));
        i+=2;
    }
    printf("\n");
}

void printUnsignedCharArray(unsigned char *arr){
    int i = 0;
    while(arr[i] != '\0') {
        printf("%c", hex_to_ascii(arr[i], arr[i+1]));
        i+=2;
    }
    printf("\n");
}