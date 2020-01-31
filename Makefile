CC = gcc

CFLAGS = -std=c99 -I./
LDFLAGS = -shared -fPIC -ldl libnexio.a

all = libnexio.a libnexmonkali.so

libnexmonkali.so: libnexio.a
	$(CC) -o libnexmonkali.so $(CFLAGS) nexmon.c $(LDFLAGS)

libnexio.a:
	$(CC) -c libnexio.c
	ar rcs libnexio.a libnexio.o

clean:
	rm libnexmonkali.so libnexio.a libnexio.o

install:
	mount -o rw,remount /system
	cp libnexmonkali.so /system/xbin
	chmod 0755 /system/xbin/libnexmonkali.so
	chmod +x /system/xbin/libnexmonkali.so
	mount -o ro,remount /system

uninstall:
	mount -o rw,remount /system
	rm /system/xbin/libnexmonkali.so
	mount -o ro,remount /system
