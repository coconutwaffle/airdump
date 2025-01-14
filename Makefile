.PHONY: all clean debug
SRC := airdump.c
OUT := airdump
FLAGS := -lpthread -O2

ifeq ($(CC), gcc)
    FLAGS += -Wall -Wextra
else ifeq ($(CC), clang)
    FLAGS += -Weverything
endif

all: $(OUT)

$(OUT): $(SRC)
	$(CC) -o $(OUT) $(SRC) $(FLAGS)

debug: $(SRC)
	$(CC) -o $(OUT) $(SRC) -DDEBUG $(FLAGS)
	
clean:
	rm -f $(OUT) *.o
