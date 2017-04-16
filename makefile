all: crypto.o socketio.o protocol.o
	gcc server.c crypto.o protocol.o socketio.o -o server/server -lgmp -g -lm
	gcc client.c crypto.o protocol.o socketio.o -o client/client -lgmp -g -lm

protocol.o: protocol.c protocol.h
	gcc -c protocol.c -g -lgmp
socketio.o: socketio.c socketio.h
	gcc -c socketio.c -g -lgmp
test: crypto.o
	gcc main.c crypto.o -o test -lgmp -g -lm
crypto.o: crypto.c crypto.h
	gcc -c crypto.c -g
