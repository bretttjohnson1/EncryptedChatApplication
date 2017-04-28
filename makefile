all: crypto.o socketio.o protocol.o hashmap.o
	gcc server.c crypto.o protocol.o socketio.o hashmap.o -o server/server -lgmp -g -lm -lpthread
	gcc client.c crypto.o protocol.o socketio.o -o client/client -lgmp -g -lm -lpthread
test: crypto.o socketio.o protocol.o hashmap.o main.c
	gcc main.c crypto.o protocol.o socketio.o -o test -lgmp -g -lm -lpthread
protocol.o: protocol.c protocol.h
	gcc -c protocol.c -g -lgmp
socketio.o: socketio.c socketio.h
	gcc -c socketio.c -g -lgmp
crypto.o: crypto.c crypto.h
	gcc -c crypto.c -g
hashmap.o: hashmap.c hashmap.h
	gcc -c hashmap.c -g
