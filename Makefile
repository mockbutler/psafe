CFLAGS += -std=c99 -Wall -g -pedantic -D_GNU_SOURCE
CFLAGS += $(shell libgcrypt-config --cflags)
LDLIBS += $(shell libgcrypt-config --libs)
CC := clang
EXE := psafe
OBJ := psafe.o

$(EXE): $(OBJ)

clean:
	$(RM) $(EXE) $(OBJ)
