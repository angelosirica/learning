#include <stdio.h>
#include "ds.h"

/* Print the given circuit
   Input : circuit, number of gates - Output : void */

void
printFunct(Gate *circuit, int l)
{
  Gate *current=circuit+l;
  if (current->type==0){
    printf("(x%d %s y%d)",current->xIndex,current->fName,current->yIndex);
    return;
  }

  printf("(");
  printFunct(circuit,current->pGate[0]);
  printf(" %s ",current->fName);
  printFunct(circuit,current->pGate[1]);
  printf(")");
}

/* Evaluate the given circuit
   Input : circuit, x values, y values, number of gates - Output : int (result for x,y) */

int
evalFunct(Gate *circuit,int *x, int *y, int l)
{
    Gate *current=circuit+(l);
    int (*gateF)(int,int)=current->funct;
    int left,right;

    if (current->type==0){
        left=x[current->xIndex];
        right=y[current->yIndex];
    }
    else {
        left=evalFunct(circuit,x,y,current->pGate[0]);
        right=evalFunct(circuit,x,y,current->pGate[1]);
    }

    return gateF(left,right);
}
