#CFLAGS = -DDEBUG -I /usr/local/opt/openssl/include/
CFLAGS =  -g -I /usr/local/opt/openssl/include/
LDFLAGS = -L/usr/lib/i386-linux-gnu/ -lssl -lcrypto
INC=-I/openssl
OBJ=funcManagement.o main.o gateFunct.o encode.o decode.o ecbaes.o select.o loadGarb.o
LOADOBJ=loadGarb.o decode.o ecbaes.o funcManagement.o gateFunct.o select.o

main: ${OBJ}
	gcc -o main ${OBJ} -lssl -lcrypto

mainecb: ecbaes.o mainecb.o
	gcc -o mainecb mainecb.o ecbaes.o -lssl -lcrypto

aes: aes.o
	gcc -o aes aes.o -lssl -lcrypto

clean:
	rm -f main ${OBJ}
	rm -f loadMain ${LOADOBJ}
	rm -f aes aes.o
	rm -f mainecb mainecb.o ecbaes.o
