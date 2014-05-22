CFLAGS += -std=c99 -Wall -g -pedantic -D_GNU_SOURCE
LDLIBS += -lgcrypt
CC := clang
EXE := psafe
OBJ := psafe.o

$(EXE): $(OBJ)

clean:
	$(RM) $(EXE) $(OBJ)
