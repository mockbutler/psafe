CFLAGS += -std=c99 -Wall -g -pedantic -D_GNU_SOURCE \
	$(shell libgcrypt-config --cflags)
LDLIBS += $(shell libgcrypt-config --libs)
SRCS = psafe.c
OBJS = $(patsubst %.c,%.o,$(SRCS))

%.o: %.cc
	$(CXX) $(CXXFLAGS) -o $@ -c $<

psafe: $(OBJS)
	$(CXX) -o psafe $+ $(LDLIBS)

depend: .depend

.depend: $(SRCS)
	$(CC) $(CFLAGS) -MM $^ > ./.depend

clean:
	$(RM) psafe $(OBJS)

distclean: clean
	$(RM) .depend

-include .depend
