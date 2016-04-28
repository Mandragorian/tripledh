.PHONY: clean distclean

tdh : privkeydh.o tdh.o dh.o
	gcc -o tdh tdh.o dh.o privkeydh.o `libgcrypt-config --libs`

dynamic: privkeydh.o tdh.o dh.so
	gcc -o tdh-dynamic tdh.o privkeydh.o -L. -ldh `libgcrypt-config --libs`

tdh-debug : privkeydh.o dh.o tdh-debug.o debug.o
	gcc -o tdh-debug tdh-debug.o dh.o privkeydh.o debug.o `libgcrypt-config --libs`

dynamic-debug: privkeydh.o tdh-debug.o dh.so debug.o
	gcc -o tdh-dynamic-debug tdh-debug.o privkeydh.o debug.o -L. -ldh `libgcrypt-config --libs`

%.o : %.c
	gcc -c $<

dh.so: dh.c
	gcc -fPIC -shared dh.c -o libdh.so

tdh-debug.o: tdh.c
	gcc -DDEBUG -c tdh.c -o tdh-debug.o

clean :
	rm -f *.o

distclean: clean
	rm -f libdh.so
	rm -f tdh
	rm -f tdh-debug
	rm -f tdh-dynamic
	rm -f tdh-dynamic-debug
