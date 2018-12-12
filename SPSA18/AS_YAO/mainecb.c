#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>

#include "templates.h"

int main (void)
{
  /* Set up the key and iv. Do I need to say to not hard code these in a
   * real application? :-)
   */

/*
const RAND_METHOD* rm = RAND_get_rand_method();
if(rm == RAND_SSLeay())
{
    printf("Using default generator\n");
}
*/

unsigned char buffer[128];
int rc = RAND_bytes(buffer, sizeof(buffer));
unsigned long err = ERR_get_error();

if(rc != 1) {
    printf("Error in generating random bytes\n");
    /* `err` is valid    */
}

/* OK to proceed */
  /* A 256 bit key */
  //unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
  unsigned char key[16];
  unsigned char iv[16];
  rc = RAND_bytes(key,16);
  rc = RAND_bytes(iv,16);

  /* A 128 bit IV */
  //unsigned char *iv = (unsigned char *)"0123456789012345";

  /* Message to be encrypted */
  unsigned char *plaintext =
                (unsigned char *)"12345The quick brown fox jumps over the lazy dog";

  /* Buffer for ciphertext. Ensure the buffer is long enough for the
   * ciphertext which may be longer than the plaintext, dependant on the
   * algorithm and mode
   */
  unsigned char ciphertext[128];

  /* Buffer for the decrypted text */
  unsigned char decryptedtext[128];

  int decryptedtext_len, ciphertext_len;


  /* Encrypt the plaintext */
  ciphertext_len = ECBencrypt(plaintext, strlen ((char *)plaintext), key, ciphertext);

  /* Do something useful with the ciphertext here */
  printf("Ciphertext is (%d):\n",ciphertext_len);
  BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

  /* Decrypt the ciphertext */
  decryptedtext_len = ECBdecrypt(ciphertext, ciphertext_len, key, decryptedtext);

  /* Add a NULL terminator. We are expecting printable text */
  decryptedtext[decryptedtext_len] = '\0';

  /* Show the decrypted text */
  printf("Decrypted text is (%d):\n",decryptedtext_len);
  printf("%s\n", decryptedtext);


  return 0;
}
