#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../YAO/ds.h"

const char * readFile(char * _filename);
void readBin(unsigned char *buf,int len, FILE *fp);
void printBinary(unsigned char *buf, int len, FILE *fp);
int generateDSAKeys();
int generateRSAKeys();
int encrytRSA();
int signDSA();
int decryptRSA();
int verifyDSAandDecrypt();
