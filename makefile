all: crypto.o socketio.o protocol.o hashmap.o
	gcc server.c crypto.o protocol.o socketio.o hashmap.o -o server/server -lgmp -g -lm -lpthread -std=gnu99 -L${HOME}/lib -I${HOME}/include
	gcc client.c crypto.o protocol.o socketio.o -o client/client -lgmp -g -lm -lpthread -std=gnu99 -L${HOME}/lib -I${HOME}/include
test: crypto.o socketio.o protocol.o hashmap.o main.c
	gcc main.c crypto.o protocol.o socketio.o -o test -lgmp -g -lm -lpthread -std=gnu99 -L${HOME}/lib -I${HOME}/include
protocol.o: protocol.c protocol.h
	gcc -c protocol.c -g -lgmp -std=gnu99 -L${HOME}/lib -I${HOME}/include
socketio.o: socketio.c socketio.h
	gcc -c socketio.c -g -lgmp -std=gnu99 -L${HOME}/lib -I${HOME}/include
crypto.o: crypto.c crypto.h
	gcc -c crypto.c -g -std=gnu99 -lgmp -L${HOME}/lib -I${HOME}/include
hashmap.o: hashmap.c hashmap.h
	gcc -c hashmap.c -g -std=gnu99
