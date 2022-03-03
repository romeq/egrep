CC=clang
CFLAGS+=-Wall -Wextra -Wpedantic -g
RELEASE_FLAGS=-O3
SRC = $(wildcard *.c)
OBJ = $(SRC:c=o)

egrp: $(OBJ)
	$(CC) $(CFLAGS) $^ -o egrp

release: $(OBJ)
	$(CC) $(CFLAGS) $(RELEASE_FLAGS) $^ -o egrp

.c.o:
	$(CC) -o $@ -c $< $(CFLAGS)

all: egrp

clean:
	rm -f *.o

.PHONY: all
