#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openssl/conf.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/rand.h"

#include "ds.h"
#include "templates.h"

/* Decode input Gate by using the y value
   Input = Input Gate, y - Output: inputWire for the next Gate */

Wire*
decodeInputGate(Gate *inputGate, int *y)
{
  int yinp = y[inputGate->yIndex];
  Wire *inputWire = (Wire*)malloc(sizeof(Wire));
  inputWire->key = (unsigned char *)malloc(KEYLEN);

  memcpy(inputWire->key,inputGate->table[yinp][0],KEYLEN);
  inputWire->bit=*inputGate->table[yinp][1];

  return inputWire;
}

/* Recorsive decode of the input and intermediate Gates.
   Input = Circuit, CurrentGate, y values - Output: wire for the next Gate */

Wire*
decodeOtherGate(Gate *circuit, Gate *currentGate, int *y)
{
  Wire* left;
  Wire* right;
  Wire* outputWire = (Wire*)malloc(sizeof(Wire));
  int r,c;
  unsigned char *ciphertext=(unsigned char *)malloc(2*KEYLEN);
  unsigned char *plaintext=(unsigned char *)malloc(2*KEYLEN);
  unsigned char *leftKey=(unsigned char *)malloc(KEYLEN);
  unsigned char *rightKey=(unsigned char *)malloc(KEYLEN);
  unsigned char *key=(unsigned char *)malloc(KEYLEN);

    if (currentGate->type == 0){
      return decodeInputGate(currentGate, y);
    }
    else {
      left = decodeOtherGate(circuit,circuit+currentGate->pGate[0],y);
      right = decodeOtherGate(circuit,circuit+currentGate->pGate[1],y);

      r = (int) left->bit;
      c = (int) right->bit;
      leftKey = left->key;
      rightKey = right->key;

      unsigned char *TABLE;
      TABLE=currentGate->table[r][c];

      // XOR Gate Optimization
      if ((currentGate->type == 1) && !strncmp(currentGate->fName,"XOR",3)){
        for (int i=0;i<KEYLEN;i++){
          plaintext[i] = *(TABLE+i)^*(rightKey+i)^*(leftKey+i);
        }
        outputWire->key = (unsigned char *)malloc(KEYLEN);
        memcpy(outputWire->key,plaintext,KEYLEN);
        outputWire->bit = TABLE[2*KEYLEN-1];
      }
      else {
        ECBdecrypt(currentGate->table[r][c], 2*KEYLEN, leftKey, ciphertext);
        ECBdecrypt(ciphertext, 2*KEYLEN, rightKey, plaintext);
        outputWire->key = (unsigned char *)malloc(KEYLEN);
        memcpy(outputWire->key,plaintext,KEYLEN);
        outputWire->bit = plaintext[2*KEYLEN-1];
      }
    }

  return outputWire;
}

/* Starting from the OUTPUT gate, this method perform the decode of the circuit
   Input = Circuit, y values, number of Gates - Output: output value of the circuit using y */

int
decode(Gate *circuit,int *y, int l)
{
  int i;
  Gate *current;
  Wire *left, *right;
  int r,c;
  unsigned char *leftKey;
  unsigned char *rightKey;
  unsigned char *ciphertext = (unsigned char *)malloc(KEYLEN);
  unsigned char *plaintext = (unsigned char *)malloc(KEYLEN);
  current = circuit+l;

  left = decodeOtherGate(circuit,circuit+(current->pGate[0]),y);
  right = decodeOtherGate(circuit,circuit+(current->pGate[1]),y);

  r = left->bit;
  c = right->bit;
  leftKey = left->key;
  rightKey = right->key;

  ECBdecrypt(current->table[r][c], KEYLEN, leftKey, ciphertext);
  ECBdecrypt(ciphertext, KEYLEN, rightKey, plaintext);

  return (int) plaintext[KEYLEN-1];
}
