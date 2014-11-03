all:
	gcc -W aes.c sha256.c client.c -o client -lgmp

clean:
	rm client

# Very funny.
measandwich:
	gcc -W aes.c sha256.c client.c -o client -lgmp

# Note, torus.cs. IP may be out of date. Confirm IP when running.
check: all
	./client -i 128.32.42.19 -c client_cert.crt -d client_private.key -m client_modulus.key
