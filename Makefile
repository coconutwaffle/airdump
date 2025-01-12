.PHONY: all clean
all:
	gcc -o airdump airdump.c
	
debug:
	gcc -o airdump airdump.c -DDEBUG
clean:
	rm airdump