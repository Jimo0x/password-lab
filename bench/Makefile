CFLAGS=-O2 -Wall -Wextra

hashbench: hashbench.c
	$(CC) $(CFLAGS) -o $@ $< -lcrypto

clean:
	rm -f hashbench
