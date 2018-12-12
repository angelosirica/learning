#include <stdio.h>
#include "ds.h"
#include "templates.h"

int
main()
{

// Initialize a 5-gates Circuit, the output gate is the last gate of the circuit
Gate circuit[]={
                    {0,0,0,0,{0,0},{2,0},"AND",andGate,{7,7},
                    {{(unsigned char *)NULL,(unsigned char *)NULL},
                     {(unsigned char *)NULL,(unsigned char *)NULL}},
                    {(unsigned  char *)NULL,(unsigned char *)NULL}},
                    {1,0,1,1,{0,0},{2,1},"OR",orGate,{7,7},
                    {{(unsigned char *)NULL,(unsigned char *)NULL},
                     {(unsigned char *)NULL,(unsigned char *)NULL}},
                     {(unsigned  char *)NULL,(unsigned char *)NULL}},
                    {2,1,5,5,{0,1},{4,0}, "XOR",xorGate,{7,7},
                    {{(unsigned char *)NULL,(unsigned char *)NULL},
                     {(unsigned char *)NULL,(unsigned char *)NULL}},
                     {(unsigned  char *)NULL,(unsigned char *)NULL}},
                     {3,0,2,2,{0,0},{4,1}, "NAND",nandGate,{7,7},
                    {{(unsigned char *)NULL,(unsigned char *)NULL},
                     {(unsigned char *)NULL,(unsigned char *)NULL}},
                     {(unsigned  char *)NULL,(unsigned char *)NULL}},
                     {4,2,5,5,{2,3},{8,8}, "NOR",norGate,{7,7},
                    {{(unsigned char *)NULL,(unsigned char *)NULL},
                     {(unsigned char *)NULL,(unsigned char *)NULL}},
                     {(unsigned  char *)NULL,(unsigned char *)NULL}},
                   };

int a,b;

// Initialization of vectors that contains x and y values for the input Gates
int x[]={0,0,0};
int y[]={0,0,0};

// Print the circuit on the default std output
printf("\n");
printf("Circuit:\n");
printFunct(circuit,4);
printf("\n\n");

/* Evaluate, encode and decode the circuit for each possible combination
of input values. Print the result on the std output */
FILE *fd;
char fileName[80];
Gate *cir;
int l;

for (a=0;a<8;a++){
    for(b=0;b<8;b++){

      x[0]=a&1;
      y[0]=b&1;
      x[1]=(a>>1)&1;
      y[1]=(b>>1)&1;
      x[2]=(a>>2)&1;
      y[2]=(b>>2)&1;

      printf("The value of the function with");
      printf("\tX=[%d,%d,%d]",x[0],x[1],x[2]);
      printf("\tY=[%d,%d,%d]\t",y[0],y[1],y[2]);
      printf("is %d\t",evalFunct(circuit,x,y,4));
      encode(circuit,x,4);
      printf("encoded value is %d \t",decode(circuit,y,4));

      sprintf(fileName,"Circuits/garCirc-%d%d%d-%d%d%d.txt",x[0],x[1],x[2],y[0],y[1],y[2]);
      fd=fopen(fileName,"w");
      fSelect(circuit,y,5,fd);
      fclose(fd);
      fd=fopen(fileName,"r");
      cir=loadCircuit(fd,&l,y);
      fclose(fd);
      //printFunct(cir,4);
      printf("and -using file- %d\n",decode(cir,y,4));

    }
  }
}
