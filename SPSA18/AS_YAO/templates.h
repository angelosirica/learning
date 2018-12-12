#include <stdio.h>
#include "ds.h"

void printFunct(Gate *,int);
int evalFunct(Gate *,int *,int *,int);
void fSelect(Gate *,int *,int,FILE *);
Gate *loadCircuit(FILE *, int *, int *);

void encode(Gate *,int *,int);
int decode(Gate *,int *,int);

int ECBencrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext);
int ECBdecrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext);



extern int andGate(int,int);
extern int nandGate(int,int);
extern int orGate(int,int);
extern int norGate(int,int);
extern int xorGate(int,int);
extern int nxorGate(int,int);
