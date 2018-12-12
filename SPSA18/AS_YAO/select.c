#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "ds.h"
#include "templates.h"

/* Print a key of a Gate in the file
   Input = key to be written, file to write on, gate type - Output: Void */

void
printKey(unsigned char *key, FILE *fd, int type){

    int i, size;
    if(type == 1) size=2*KEYLEN;
    else size = KEYLEN;
    for(i=0;i<size;i++){
        fprintf(fd,"%d ",(unsigned int) key[i]);
    }
    fprintf(fd,"\n");

}

/* Print an Output Gate in the file
   Input = Pointer to the Gate, file to write on - Output: Void */

void
printOutputGate(Gate *gate, FILE *fd)
{

        fprintf(fd,"%d %d\n",gate->pGate[0],gate->pGate[1]);
        fprintf(fd,"%s\n",gate->fName);
        printKey(gate->table[0][0],fd,2);
        printKey(gate->table[0][1],fd,2);
        printKey(gate->table[1][0],fd,2);
        printKey(gate->table[1][1],fd,2);
        fprintf(fd,"\n");

}

/* Print an Intermediate Gate in the file
   Input = Pointer to the Gate, file to write on - Output: Void */

void
printIntermediateGate(Gate *gate, FILE *fd)
{
    fprintf(fd,"%d %d\n",gate->pGate[0],gate->pGate[1]);
    fprintf(fd,"%s\n",gate->fName);
    fprintf(fd,"%d %d\n",gate->nGate[0],gate->nGate[1]);
    printKey(gate->table[0][0],fd,1);
    printKey(gate->table[0][1],fd,1);
    printKey(gate->table[1][0],fd,1);
    printKey(gate->table[1][1],fd,1);
    fprintf(fd,"\n");
}

/* Print an Input Gate in the file
   Input = Pointer to the Gate, file to write on, the y values - Output: Void */

void
printInputGate(Gate *gate, FILE *fd, int *y)
{
    fprintf(fd,"%d\n",gate->yIndex);
    fprintf(fd,"%d %d\n",gate->nGate[0],gate->nGate[1]);
    fprintf(fd,"%s\n",gate->fName);
    printKey(gate->table[y[gate->yIndex]][0],fd,0);
    fprintf(fd,"%d\n",*(gate->table[y[gate->yIndex]][1]));
    fprintf(fd,"\n");
}

/* Print the given circuit on a File, invoking the appropiate functions
   Input = Pointer to Circuit, file to write on, the y values, the number of gates - Output: Void */

void
fSelect(Gate *circuit, int *y, int l, FILE *fd)
{

    int i;
    Gate *current;

    fprintf(fd,"%d\n\n",l);
    for(i=0;i<l;i++){
        current=circuit+i;

        fprintf(fd,"%d %d\n",current->index,current->type);

        // OutputGate
        if(current->type==2){
            printOutputGate(current,fd);
            continue;
        }
        // IntermediateGate
        if(current->type==1){
          printIntermediateGate(current,fd);
          continue;
        }

        // InputGate
        if(current->type==0){
          printInputGate(current,fd,y);
          continue;
        }
    }
}
