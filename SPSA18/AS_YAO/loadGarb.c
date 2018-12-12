#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ds.h"
#include "templates.h"

/* Read a key of a Gate from a given file
   Input = key to be red, file to read from, gate type - Output: Void */

void
readKey(unsigned char *key, FILE *fd,int type){
    int i,t,size;

    if(type == 1) size=2*KEYLEN;
    else size = KEYLEN;
    for(i=0;i<size;i++){
        fscanf(fd,"%d",&t);
        key[i]=(unsigned char) t;
    }

}

/* Add the function to a given Gate by reading from a given file
   Input: Pointer to the gate - Output: Void */

void
addFunct(Gate *current)
{

    int len;

    len=strlen(current->fName);

    if (len==3){
        if (!strcmp(current->fName,"AND")) current->funct=andGate;
        if (!strcmp(current->fName,"NOR")) current->funct=norGate;
        if (!strcmp(current->fName,"XOR")) current->funct=xorGate;
        return;
    }

    if (len==4){
        if (!strcmp(current->fName,"NAND")) current->funct=nandGate;
        if (!strcmp(current->fName,"NXOR")) current->funct=nxorGate;
        return;
    }

    current->funct=orGate;

}

/* Load an output Gate by reading from a given file
   Input: Pointer to the gate, file to read from - Output: Void */

void
loadOutput(Gate *gate, FILE *fd)
{
  fscanf(fd,"%d %d",&(gate->pGate[0]),&(gate->pGate[1]));
  gate->fName=(char *)malloc(6);
  fscanf(fd,"%s",gate->fName);
  gate->table[0][0]=(unsigned char *)malloc(KEYLEN);
  readKey(gate->table[0][0],fd,2);
  gate->table[0][1]=(unsigned char *)malloc(KEYLEN);
  readKey(gate->table[0][1],fd,2);
  gate->table[1][0]=(unsigned char *)malloc(KEYLEN);
  readKey(gate->table[1][0],fd,2);
  gate->table[1][1]=(unsigned char *)malloc(KEYLEN);
  readKey(gate->table[1][1],fd,2);
}

/* Load an Intermediate Gate by reading from a given file
   Input: Pointer to the gate, file to read from - Output: Void */

void
loadIntermediate(Gate *gate, FILE *fd)
{
  fscanf(fd,"%d %d",&(gate->pGate[0]),&(gate->pGate[1]));
  gate->fName=(char *)malloc(6);
  fscanf(fd,"%s",gate->fName);
  fscanf(fd,"%d %d",&(gate->nGate[0]),&(gate->nGate[1]));
  gate->table[0][0]=(unsigned char *)malloc(2*KEYLEN);
  readKey(gate->table[0][0],fd,1);
  gate->table[0][1]=(unsigned char *)malloc(2*KEYLEN);
  readKey(gate->table[0][1],fd,1);
  gate->table[1][0]=(unsigned char *)malloc(2*KEYLEN);
  readKey(gate->table[1][0],fd,1);
  gate->table[1][1]=(unsigned char *)malloc(2*KEYLEN);
  readKey(gate->table[1][1],fd,1);
}

/* Load an Input Gate by reading from a given file
   Input: Pointer to the gate, file to read from, y values - Output: Void */

void
loadInput(Gate *gate, FILE *fd, int *y)
{
  int t;

  fscanf(fd,"%d",&(gate->yIndex));
  fscanf(fd,"%d %d",&(gate->nGate[0]),&(gate->nGate[1]));
  gate->fName=(char *)malloc(6);
  fscanf(fd,"%s",gate->fName);
  gate->table[y[gate->yIndex]][0]=(unsigned char *)malloc(KEYLEN);
  readKey(gate->table[y[gate->yIndex]][0],fd,0);
  fscanf(fd,"%d",&t);
  gate->table[y[gate->yIndex]][1]=(unsigned char *)malloc(1);
  gate->table[y[gate->yIndex]][1][0]=(unsigned char)t;
  addFunct(gate);
}

/* Load a circuit from a given file
   Input: File to read from, number of gates, y values - Output: Pointer to the circuit */

Gate *
loadCircuit(FILE *fd, int *l,int *y)
{

    int i,len;
    Gate *current;
    fscanf(fd,"%d",l);  //number of gates

    Gate *circuit=malloc(*l*sizeof(Gate));

    for(i=0;i<(*l);i++){
        current=circuit+i;

        fscanf(fd,"%d %d",&(current->index),&(current->type));
        if(current->type==2){
            loadOutput(current,fd);
            addFunct(current);
            continue;
        }

        if(current->type==1){
            loadIntermediate(current,fd);
            addFunct(current);
            continue;
        }

        if(current->type==0){
            loadInput(current,fd,y);
            addFunct(current);
            continue;
        }

    }
    return circuit;

}
