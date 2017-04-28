all: crypto.o socketio.o protocol.o hashmap.o
	gcc server.c crypto.o protocol.o socketio.o hashmap.o -o server/server -lgmp -g -lm -lpthread -std=gnu99
	gcc client.c crypto.o protocol.o socketio.o -o client/client -lgmp -g -lm -lpthread -std=gnu99
test: crypto.o socketio.o protocol.o hashmap.o main.c
	gcc main.c crypto.o protocol.o socketio.o -o test -lgmp -g -lm -lpthread -std=gnu99
protocol.o: protocol.c protocol.h
	gcc -c protocol.c -g -lgmp -std=gnu99
socketio.o: socketio.c socketio.h
	gcc -c socketio.c -g -lgmp -std=gnu99
crypto.o: crypto.c crypto.h
	gcc -c crypto.c -g -std=gnu99
hashmap.o: hashmap.c hashmap.h
	gcc -c hashmap.c -g -std=gnu99
