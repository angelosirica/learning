/* This file contains the main structures used by the program in order
   to encode and evaluate garbled circuits */

#ifndef _DS

typedef struct {
    int index;
    int type;           // 0--> Input Gate, 1--> Intermediate Gate, 2--> Output Gate
    int xIndex;         // only for input gates
    int yIndex;         // only for input gates
    int pGate[2];       // only for non-input gates: index of previous gates
    int nGate[2];       // only for non-output gates: index of the next gate and L or R position
    char *fName;        // function associated to the gate
    int (*funct)(int,int);      // function prototype
    unsigned int gb[2];         // garbling bits
    unsigned char *table[2][2]; // table of "envelops"
    unsigned char *keys[2];     // keys of the gate
} Gate;

typedef struct {
  unsigned char *key;
  unsigned char bit;
} Wire;

#define KEYLEN 16

#define _DS

#endif
