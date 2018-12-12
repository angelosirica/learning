#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "ds.h"
#include "templates.h"

void encodeOutput(Gate *,Gate *);
void encodeInput(Gate *,Gate *,int *);
void encodeIntermediate(Gate *,Gate *);

/* This function performs the encoding of a given circuit
   Input: a circuit, the x values, the number of gates */

void
encode(Gate *circuit,int *x,int l)
{
    int i;
    Gate *current;

    for(i=0;i<=l;i++){
        current=circuit+i;

        RAND_bytes((unsigned char *)current->gb,4);
        current->gb[0]%=2;
        RAND_bytes((unsigned char *)((current->gb)+1),4);
        current->gb[1]%=2;

        current->keys[0]=(unsigned char *)malloc(KEYLEN);
        current->keys[1]=(unsigned char *)malloc(KEYLEN);
        RAND_bytes((unsigned char *)current->keys[0],KEYLEN);
        RAND_bytes((unsigned char *)current->keys[1],KEYLEN);

#ifdef DEBUG
printf("Gate %d\n",i);
printf("Key 0\n");
BIO_dump_fp (stdout,(const char *)current->keys[0],KEYLEN);
printf("Key 1\n");
BIO_dump_fp (stdout,(const char *)current->keys[1],KEYLEN);
printf("Garbling bit 0: %d\n",current->gb[0]);
printf("Garbling bit 1: %d\n",current->gb[1]);
printf("\n\n");
#endif

    }

    for(i=0;i<=l;i++){
        current=circuit+i;
        if (current->type==2)
            encodeOutput(circuit,current);
        if (current->type==1)
            encodeIntermediate(circuit,current);
        if (current->type==0)
            encodeInput(circuit,current,x);
    }
}


/* This function performs the encoding of an Output Gate
   Input: a circuit, the Output Gate */

void
encodeOutput(Gate *circuit,Gate *current)
{
    int b0,b1;
    int r,c;
    int res;
    Gate *p0,*p1;
    unsigned char *plaintext =(unsigned char *)malloc(KEYLEN);
    unsigned char *ciphertext=(unsigned char *)malloc(KEYLEN);

    b0=current->gb[0]; p0=circuit+current->pGate[0];
    b1=current->gb[1]; p1=circuit+current->pGate[1];
    for(r=0;r<2;r++){
        for(c=0;c<2;c++){
            res=current->funct(r^b0,c^b1);
            RAND_bytes((unsigned char *)plaintext,KEYLEN);
            if(res) plaintext[KEYLEN-1]=(unsigned char)0x01;
               else plaintext[KEYLEN-1]=(unsigned char)0x00;
            current->table[r][c]=(unsigned char *)malloc(KEYLEN);
            ECBencrypt(plaintext,KEYLEN,p1->keys[c^b1],ciphertext);
            ECBencrypt(ciphertext,KEYLEN,p0->keys[r^b0],current->table[r][c]);

#ifdef DEBUG
  printf("table[%d][%d] holding result for (%d,%d)\n",r,c,b0^r,b1^c);
  printf("Plaintext: \n");
  BIO_dump_fp (stdout,(const char *)plaintext,KEYLEN);
  printf("with key:\n");
  BIO_dump_fp (stdout,(const char *)p1->keys[c^b1],KEYLEN);
  printf("obtaining:\n");
  BIO_dump_fp (stdout,(const char *)ciphertext,KEYLEN);
  printf("with key:\n");
  BIO_dump_fp (stdout,(const char *)p0->keys[r^b0],KEYLEN);
  printf("obtaining:\n");
  BIO_dump_fp (stdout,(const char *)current->table[r][c],KEYLEN);
  printf("\n\n\n");
#endif
        }
    }
}

/* This function performs the encoding of a Intermediate Gate
   Input: a circuit, the Intermediate Gate */

void
encodeIntermediate(Gate *circuit,Gate *current)
{
    int b0,b1;
    int r,c;
    int res, bit;
    int ngb;
    Gate *p0,*p1;
    Gate *ng;

    // The plaintext and the ciphertext will contain 256 bits that represent a key and
    // a row/column indication (or their encryption)

    b0 = current->gb[0]; p0 = circuit+current->pGate[0];
    b1 = current->gb[1]; p1 = circuit+current->pGate[1];
    ng = circuit+current->nGate[0];
    ngb = ng->gb[current->nGate[1]];

    unsigned char *TABLE;
    for(r=0;r<2;r++){
        for(c=0;c<2;c++){
          res=current->funct(r^b0,c^b1);
          current->table[r][c]=(unsigned char *)malloc(2*KEYLEN);
          TABLE=current->table[r][c];

          // XOR Gate Optimization
          if (!strncmp(current->fName,"XOR",3)){
            unsigned char *p1k = p1->keys[c^b1];
            unsigned char *p0k = p0->keys[r^b0];
            for (int i=0;i<KEYLEN;i++)
                *(TABLE+i)=*(current->keys[res]+i)^*(p1k+i)^*(p0k+i);
            *(TABLE+2*KEYLEN-1)=(unsigned char)res^ngb;
          }
          else {
                unsigned char *plaintext =(unsigned char *)malloc(2*KEYLEN);
                unsigned char *ciphertext=(unsigned char *)malloc(2*KEYLEN);
                memcpy(plaintext,current->keys[res],KEYLEN);
                if(res^ngb) plaintext[2*KEYLEN-1]=(unsigned char)0x01;
                    else plaintext[2*KEYLEN-1]=(unsigned char)0x00;
                ECBencrypt(plaintext, 2*KEYLEN,p1->keys[c^b1],ciphertext);
                ECBencrypt(ciphertext,2*KEYLEN,p0->keys[r^b0],TABLE);
          }


#ifdef DEBUG
  printf("table[%d][%d] holding result for (%d,%d)\n",r,c,b0^r,b1^c);
  printf("Plaintext: \n");
  BIO_dump_fp (stdout,(const char *)plaintext,KEYLEN);
  printf("with key:\n");
  BIO_dump_fp (stdout,(const char *)p1->keys[c^b1],KEYLEN);
  printf("obtaining:\n");
  BIO_dump_fp (stdout,(const char *)ciphertext,KEYLEN);
  printf("with key:\n");
  BIO_dump_fp (stdout,(const char *)p0->keys[r^b0],KEYLEN);
  printf("obtaining:\n");
  BIO_dump_fp (stdout,(const char *)current->table[r][c],KEYLEN);
  printf("\n\n\n");
#endif
        }
    }
}

/* This function performs the encoding of an Input Gate
   Input: a circuit, the Input Gate */

void
encodeInput(Gate *circuit,Gate *current,int *x)
{
    int res;
    int yinp,xinp=x[current->xIndex];
    Gate *ng=circuit+current->nGate[0];
    int ngb=ng->gb[current->nGate[1]];

    for(yinp=0;yinp<2;yinp++){
        res=current->funct(xinp,yinp);
        current->table[yinp][0]=(unsigned char *)malloc(KEYLEN);
        memcpy(current->table[yinp][0],current->keys[res],KEYLEN);
        current->table[yinp][1]=(unsigned char *)malloc(1);
        *current->table[yinp][1]=(unsigned char) res^ngb;
    }

#ifdef DEBUG
    printf("Input gate %d\n",current->index);
    printf("Key 0:\n");
    BIO_dump_fp (stdout,(const char *)current->keys[0],KEYLEN);
    printf("Key 1:\n");
    BIO_dump_fp (stdout,(const char *)current->keys[1],KEYLEN);
    printf("\n\n");
#endif

}
