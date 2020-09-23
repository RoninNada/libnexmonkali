CC = gcc

CFLAGS = -std=c99 -I./
LDFLAGS = -shared -fPIC -ldl libnexio.a

all: libnexio.a libnexmonkali.so

libnexmonkali.so: libnexio.a nexmon.c
	$(CC) -o libnexmonkali.so $(CFLAGS) nexmon.c $(LDFLAGS)

libnexio.a:
	$(CC) -c libnexio.c
	ar rcs libnexio.a libnexio.o

clean:
	rm libnexmonkali.so libnexio.a libnexio.o
	
install:
	cp libnexmonkali.so /usr/lib/
	chmod 0755 /usr/lib/libnexmonkali.so
	chmod +x /usr/lib/libnexmonkali.so

uninstall:
	rm /usr/lib/libnexmonkali.so
