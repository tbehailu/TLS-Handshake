all:
	gcc -W aes.c sha256.c client.c -o client -lgmp

clean:
	rm client

# Very funny.
measandwich:
	gcc -W aes.c sha256.c client.c -o client -lgmp

# will suppress errors. be careful!
debug:
	gcc -ggdb -w aes.c sha256.c client.c -o client -lgmp

# Note, torus IP may be out of date. Confirm IP when running.
check: all
	./client -i 128.32.42.19 -c client_cert.crt -d client_private.key -m client_modulus.key

new_server: all
	./client -i 54.69.173.166 -c client_cert.crt -d client_private.key -m client_modulus.key

newer_server: all
	./client -i 54.148.53.246 -c client_cert.crt -d client_private.key -m client_modulus.key