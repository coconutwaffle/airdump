.PHONY: all clean
all:
	gcc -o airdump airdump.c
	

clean:
	rm airdump