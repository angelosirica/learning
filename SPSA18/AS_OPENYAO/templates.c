#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utilities.h"


const char *
readFile(char * filename)
{
  FILE * ciphertxt = fopen(filename,"r");                    // Read the file
  fseek(ciphertxt, 0L, SEEK_END);                            // Get the file size
  int fsize = ftell(ciphertxt);
  fseek(ciphertxt, 0L, SEEK_SET);                            // Set back to normal

  const char *indata = malloc(fsize);                        // Allocate memory for the entire file

  fread((void *) indata,sizeof(char),fsize, ciphertxt);      //Read Entire File

  return indata;
}

void
readBin(unsigned char *buf,int len, FILE *fp){
    int i,t;
    for(i=0;i<len;i++){
        fscanf(fp,"%d",&t);
        buf[i]=(unsigned char) t;
    }
}

void
printBinary(unsigned char *buf, int len, FILE *fp)
{
    int i;
    for(i=0;i<len;i++) fprintf(fp,"%d ",(unsigned int) buf[i]);
    fprintf(fp,"\n");
}
