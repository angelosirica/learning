#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "algorithms.h"
#include "utilities.h"
#include "../YAO/templates.h"
#include "../YAO/ds.h"

/*
 * OpenSSL-YAO implementation
 * ----------------------------
 *   This program generates RSA and DSA Keys, then reads a file that contains a YAO's garbled circuit,
 *   it encrypts it using RSA Keys and then signs its encryption using DSA Keys with the algorithms defined in algorithms.h.
 *   Then the execution continues with the verification of the signature and the decryption of the file and finally
 *   with the evaluation of the circuit.
 *
 *   For simplicity, no input are foreseen.
 *
 *   Return 0 = No error
 *   Return 1 = File related error
 *   Return 2 = Key reading related error
 *   Return 3 = Context related error
 *   Return 4 = EVP_*_Init related error
 *   Return 5 = EVP_*_Update related error
 *   Return 6 = EVP_*_Final related error
 */

int
main(int argc, char *argv[])
{
  #define ANSI_COLOR_YELLOW  "\x1b[33m"
  #define ANSI_COLOR_CYAN    "\x1b[36m"
  #define ANSI_COLOR_RESET   "\x1b[0m"

  int DSAKeyGeneration;
  int RSAKeyGeneration;
  int encrypt;
  int sign;
  int verDec;

  printf(ANSI_COLOR_YELLOW "\n------------- SPSA 2018 - OPENSSL/YAO -------------\n\n");
  printf("Starting...\n\n" ANSI_COLOR_CYAN);

  if((DSAKeyGeneration = generateDSAKeys()) != 0){
    return DSAKeyGeneration;
  }
  else {
    if((RSAKeyGeneration = generateRSAKeys()) != 0) {
      return RSAKeyGeneration;
    }
    else {
      if((encrypt = encrytRSA()) != 0) {
        return encrypt;
      }
      else {
        if((sign = signDSA()) != 0) {
          return sign;
        }
        else {
          if((verDec = verifyDSAandDecrypt()) != 0) {
            return verDec;
          }
        }
      }
    }
  }

  /* Evaluate the circuit using y=[0,0,0] */
  int y[]={0,0,0};
  int l= 5;
  FILE * fd=fopen("CIT/Plaintext","r");
  Gate * cir=loadCircuit(fd,&l,y);
  fclose(fd);
  printf("The decoded value is: %d\n\n",decode(cir,y,4));

  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();

  printf(ANSI_COLOR_YELLOW "\n---------------- END ----------------\n\n" ANSI_COLOR_RESET);

  return 0;
}
