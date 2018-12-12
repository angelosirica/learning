CFLAGS =  -g -I /usr/local/opt/openssl/include/
INC=-I/openssl
OBJ=openyao.o templates.o openf.o ../YAO/decode.o ../YAO/ecbaes.o ../YAO/loadGarb.o ../YAO/gateFunct.o


openyao: ${OBJ}
	gcc -o openyao ${OBJ} -lssl -lcrypto
	gcc -o openf ${OBJ} -lssl -lcrypto
	gcc -o loadGarb ${OBJ} -lssl -lcrypto
	gcc -o decode ${OBJ} -lssl -lcrypto

clean:
	rm -f ${OB}
	rm  KEYS/RSA/*
	rm  KEYS/DSA/*
	rm  SIGN/*
	rm  CIT/*
