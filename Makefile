CC = gcc
CFLAGS = -O -I include -static-libgcc

SRC	 = pcapdump.c qqlog.c
OBJS = pcapdump.o qqlog.o
LIBS = -L. -lws2_32

.c.o:
	${CC} ${CFLAGS} -c -o $*.o $<

all: ${OBJS}
	${CC} ${CFLAGS} -o pcapdump.exe ${OBJS} $(LIBS)

clean:
	rm -f ${OBJS} pcapdump.exe


