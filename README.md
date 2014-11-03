# CS 162 Project 1 - TLS Implementation

## Authors:

- Ivan Smirnov
- Tsion Behailu


## ToDo

1. fill in perform_rsa() function with project 0 solution.
2. implement send_tls_message() and receive_tls_message()
3. implement decrypt_cert()
4. implement compute_master_secret(). use random_int()
5. implement decrypt_verify_master_secret()
6. fill out main
7. Write up answers in writeup file.
8. submit
9. Drink heavily in celebration!

## Random

- figure out why we need msg_type in receive_tls_message


## NOTES

1. Be sure that only client.c is modified, otherwise autograder will fail
2. Remember to check for errors and gracefully abort