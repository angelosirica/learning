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

/* Generate DSA Keys and store them in files, then print the keys
   Input : None - Output: (int) Execution Control */

int
generateDSAKeys()
{
  // Generate DSA Keys
  printf("\n**** DSA Keys Generation ****\n\n");

  EVP_PKEY_CTX *ctx_dsaparams=EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
  EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx_dsaparams,OSKEYLEN);
  EVP_PKEY_paramgen_init(ctx_dsaparams);
  EVP_PKEY* pdsakey_params=NULL;
  EVP_PKEY_paramgen(ctx_dsaparams, &pdsakey_params);

  EVP_PKEY_CTX *ctxdsa=EVP_PKEY_CTX_new(pdsakey_params,NULL);
  EVP_PKEY_keygen_init(ctxdsa);
  EVP_PKEY* pdsakey=NULL;
  EVP_PKEY_keygen(ctxdsa,&pdsakey);

  EVP_PKEY_free(pdsakey_params);
  EVP_PKEY_CTX_free(ctx_dsaparams);
  EVP_PKEY_CTX_free(ctxdsa);

  // Write Public and Private Keys in relative files
  FILE *publicDSAFile=fopen("KEYS/DSA/pubDSAKey","w");
  FILE *privateDSAFile=fopen("KEYS/DSA/priDSAKey","w");
  FILE *privateDSA_unFile=fopen("KEYS/DSA/unpriDSAKey","w");

  if(publicDSAFile==NULL){
    fprintf(stderr,"Could not open the Public DSA Key File\n");
    return 1;
  }
  else {
      PEM_write_PUBKEY(publicDSAFile,pdsakey);
      fclose(publicDSAFile);
  }

  if(privateDSAFile==NULL){
    fprintf(stderr,"Could not open the Private DSA Key File\n");
    return 1;
  }
  else {
      PEM_write_PrivateKey(privateDSAFile,pdsakey,armorAlgo,NULL,0,NULL,passphrase);
      fclose(privateDSAFile);
  }

  if(privateDSA_unFile==NULL){
    fprintf(stderr,"Could not open the Unprotected Private DSA Key File\n");
    return 1;
  }
  else {
      PEM_write_PrivateKey(privateDSA_unFile,pdsakey,NULL,NULL,0,NULL,NULL);
      fclose(privateDSA_unFile);
  }

  // Read RSA Keys and print via BIO
  publicDSAFile=fopen("KEYS/DSA/pubDSAKey","r");
  privateDSA_unFile=fopen("KEYS/DSA/unpriDSAKey","r");
  EVP_PKEY *publicDSAKey=PEM_read_PUBKEY(publicDSAFile,NULL,NULL,NULL);
  EVP_PKEY *privateDSAKey=PEM_read_PrivateKey(privateDSA_unFile,NULL,NULL,NULL);

  if(publicDSAKey!=NULL){
      printf("Printing the DSA Public key\n");
      DSA *dsa=EVP_PKEY_get1_DSA(publicDSAKey);
      BIO *b=BIO_new(BIO_s_file());
      BIO_set_fp(b,stdout,BIO_NOCLOSE);
      DSA_print(b,dsa,0);
      printf("\n");
  } else {
    fprintf(stderr, "Could not read the Public DSA Key from the file" );
    return 2;
    }

  if(privateDSAKey!=NULL){
      printf("Printing the DSA Private key\n");
      DSA *dsa=EVP_PKEY_get1_DSA(privateDSAKey);
      BIO *b=BIO_new(BIO_s_file());
      BIO_set_fp(b,stdout,BIO_NOCLOSE);
      DSA_print(b,dsa,0);
      printf("\n\n");
  } else {
      fprintf(stderr, "Could not read the Private DSA Key from the file" );
      return 2;
    }

  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();

  return 0;
}


/* Generate RSA Keys and store them in files
   Input : None - Output: (int) Execution Control */

int
generateRSAKeys()
{
  // Generate RSA Keys
  printf("\n**** RSA Keys Generation ****\n\n");

  EVP_PKEY_CTX *ctxrsa;
  EVP_PKEY *prsakey=NULL;
  ctxrsa=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,NULL);
  EVP_PKEY_keygen_init(ctxrsa);
  EVP_PKEY_CTX_set_rsa_keygen_bits(ctxrsa,OSKEYLEN);
  EVP_PKEY_keygen(ctxrsa, &prsakey);

  FILE *publicRSAFile=fopen("KEYS/RSA/pubRSAKey","w");
  FILE *privateRSAFile=fopen("KEYS/RSA/priRSAKey","w");
  FILE *privateRSA_unFile=fopen("KEYS/RSA/unpriRSAKey","w");

  // Write Public and Private Keys in relative files
  if(publicRSAFile==NULL){
    fprintf(stderr,"Could not open Public RSA Key File\n");
    return 1;
  }
  else {
    PEM_write_PUBKEY(publicRSAFile,prsakey);
    fclose(publicRSAFile);
  }

  if(privateRSAFile==NULL){
    fprintf(stderr,"Could not open the Private RSA Key File\n");
    return 1;
  }
  else {
      PEM_write_PrivateKey(privateRSAFile,prsakey,armorAlgo,NULL,0,NULL,passphrase);
      fclose(privateRSAFile);
  }


  if(privateRSA_unFile==NULL){
      fprintf(stderr,"Could not open the Unprotected Private RSA Key File\n");
      return 1;
  }
  else {
      PEM_write_PrivateKey(privateRSA_unFile,prsakey,NULL,NULL,0,NULL,NULL);
      fclose(privateRSA_unFile);
  }

  publicRSAFile=fopen("KEYS/RSA/pubRSAKey","r");
  privateRSAFile=fopen("KEYS/RSA/priRSAKey","r");

  EVP_PKEY *publicKey=PEM_read_PUBKEY(publicRSAFile,NULL,NULL,NULL);
  EVP_PKEY *privateKey=PEM_read_PrivateKey(privateRSA_unFile,NULL,NULL,passphrase);

  if(publicKey!=NULL){
      printf("Printing the RSA Public Key\n");
      RSA *rsa=EVP_PKEY_get1_RSA(publicKey);
      BIO *b=BIO_new(BIO_s_file());
      BIO_set_fp(b,stdout,BIO_NOCLOSE);
      RSA_print(b,rsa,0);
      printf("\n");
  }

  if(privateKey!=NULL){
      printf("Printing the RSA Private Key\n");
      RSA *rsa=EVP_PKEY_get1_RSA(privateKey);
      BIO *b=BIO_new(BIO_s_file());
      BIO_set_fp(b,stdout,BIO_NOCLOSE);
      RSA_print(b,rsa,0);
      printf("\n\n");
  }

  return 0;
}

/* Encrypting the circuit file using RSA Public Key
   Input : none - Output : (int) Execution control */

int
encrytRSA()
{
  // Encrypt the file using RSA Keys
  FILE * publicFile=fopen("KEYS/RSA/pubRSAKey","r");

  // An array of one public key - you can potentially
  // have multiple public key (one per each sender)
  EVP_PKEY *publicKey[1];
  publicKey[0]=PEM_read_PUBKEY(publicFile,NULL,NULL,NULL);
  if (publicKey[0]==NULL){
      fprintf(stderr,"Could not read key from the File\n");
      ERR_print_errors_fp(stderr);
      return 1;
  }

  EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();

  if(ctx==NULL){
      fprintf(stderr,"Could not create context\n");
      ERR_print_errors_fp(stderr);
      return 3;
  }

  int ekl;
  unsigned char *ek[1];
  int lenek=EVP_PKEY_size(publicKey[0]);
  ek[0]=malloc(lenek);
  int leniv=EVP_CIPHER_iv_length(blockCipher);
  unsigned char *iv=malloc(leniv);

  if(1!=EVP_SealInit(ctx,blockCipher,ek,&ekl,iv,publicKey,1)){
      fprintf(stderr,"Could not init\n");
      ERR_print_errors_fp(stderr);
      return 4;
  }

  unsigned char ciphertext[2000];
  int len, ciphertext_len;

  // Read the circuit file
  const char * indata = readFile(filename);

  printf("Encrypting the garbling circuit:\n\n%s\n",indata);
  if(1!=EVP_SealUpdate(ctx, ciphertext, &len,(const unsigned char *) indata,strlen(indata)+1)){
      fprintf(stderr,"Could not update\n");
      ERR_print_errors_fp(stderr);
      return 5;
  }

  ciphertext_len = len;

  if(1 != EVP_SealFinal(ctx, ciphertext + len, &len)){
      fprintf(stderr,"Could not finalize\n");
      ERR_print_errors_fp(stderr);
      return 6;
  }

  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();

  FILE *ctFile=fopen("CIT/Ciphertext","w");
  if(ctFile==NULL){
      fprintf(stderr,"Could not open the Ciphertext File\n");
      return 1;
  }

  fprintf(ctFile,"%d\n",ciphertext_len);
  printBinary(ciphertext,ciphertext_len,ctFile);
  printBinary(ek[0],lenek,ctFile);
  printBinary(iv,leniv,ctFile);
  fclose(ctFile);

  return 0;
}


/* Sign the ciphertext file using the Private DSA Key
   Input : none - Output : (int) Execution control */

int
signDSA()
{

  FILE * publicDSAFile=fopen("KEYS/DSA/pubDSAKey","r");
  FILE * privateDSAFile=fopen("KEYS/DSA/priDSAKey","r");
  FILE * privateDSA_unFile=fopen("KEYS/DSA/unpriDSAKey","r");

  if(privateDSA_unFile==NULL){
    fprintf(stderr,"Could not open Unprotected Private DSA Key File\n");
    return 1;
  }

  EVP_PKEY *publicDSAKey=PEM_read_PUBKEY(publicDSAFile,NULL,NULL,NULL);
  EVP_PKEY *privateDSAKey=PEM_read_PrivateKey(privateDSA_unFile,NULL,NULL,NULL);

  EVP_MD_CTX *mdctx = NULL;

  unsigned char *sig = NULL;

  if(!(mdctx = EVP_MD_CTX_create())){
      fprintf(stderr,"Could not create context\n");
      return 3;
  }

  if(1 != EVP_DigestSignInit(mdctx,NULL,MDAlgo,NULL,privateDSAKey)){
      fprintf(stderr,"Could not create init\n");
      return 4;
  }


  /* Read the encrypted circuit file */

  const char * indatac = readFile("CIT/Ciphertext");

  printf("Message to be signed: %s\n",indatac);
  if(1 != EVP_DigestSignUpdate(mdctx, indatac, strlen(indatac))){
      fprintf(stderr,"Could not create update\n");
      return 5;
  }


  size_t slen;
  if(1 != EVP_DigestSignFinal(mdctx,NULL, &slen)){
      fprintf(stderr,"Could not finalize\n");
      return 6;
  }

  sig=malloc(slen);

  if(1!=EVP_DigestSignFinal(mdctx, sig,(size_t *)&slen)){
      fprintf(stderr,"Could not finalize2\n");
      return 6;
  }

  FILE *signatureFile=fopen("SIGN/SignatureFile","w");
  if (signatureFile != NULL)
  fprintf(signatureFile,"%d\n",(int) slen);
  printBinary(sig,slen,signatureFile);
  fclose(signatureFile);

  return 0;
}


/* Decrypt the ciphertext file using the Private RSA Key
   Input : none - Output : (int) Execution control */

int
decryptRSA()
{
  /* Decrypt the file */
  FILE * privateRSAFile=fopen("KEYS/RSA/unpriRSAKey","r");
  if(privateRSAFile==NULL){
      fprintf(stderr,"Could not open Private RSA Key File\n");
      return 1;
      }

  EVP_PKEY * privateRSAKey=PEM_read_PrivateKey(privateRSAFile,NULL,NULL,passphrase);
  if (privateRSAKey==NULL){
      fprintf(stderr,"Could not read key from the Unprotected Private RSA Key File");
      ERR_print_errors_fp(stderr);
      return 2;
  }

  FILE *ctFile=fopen("CIT/Ciphertext","r");
  int ciphertext_len;
  fscanf(ctFile,"%d",&ciphertext_len);
  const unsigned char *ciphertext=malloc(ciphertext_len);
  readBin((unsigned char *)ciphertext,ciphertext_len,ctFile);

  EVP_CIPHER_CTX *ctxcip=EVP_CIPHER_CTX_new();

  if(ctxcip==NULL){
      fprintf(stderr,"Could not create context\n");
      ERR_print_errors_fp(stderr);
      return 3;
  }


  int ersaklen=EVP_PKEY_size(privateRSAKey);
  unsigned char *ekrsa=malloc(ersaklen);
  readBin(ekrsa,ersaklen,ctFile);
  int ivlencip=EVP_CIPHER_iv_length(blockCipher);
  unsigned char *ivcip=malloc(ivlencip);
  readBin(ivcip,ivlencip,ctFile);
  if(1!=EVP_OpenInit(ctxcip,blockCipher,ekrsa,ersaklen,ivcip,privateRSAKey)){
      fprintf(stderr,"Could not init\n");
      ERR_print_errors_fp(stderr);
      return 4;
  }

  unsigned char plaintext[200000];
  int lencip;
  if(1!=EVP_OpenUpdate(ctxcip,plaintext,&lencip,ciphertext,ciphertext_len)){
      fprintf(stderr,"Could not update\n");
      ERR_print_errors_fp(stderr);
      return 5;
  }
  int plaintext_len = lencip;
  if(1!=EVP_OpenFinal(ctxcip, plaintext + lencip, &lencip)){
      fprintf(stderr,"Could not finalize\n");
      ERR_print_errors_fp(stderr);
      return 6;
  }

  printf("Decrypting:\n\n%s\n",plaintext);
  FILE * plaintextFile = fopen("CIT/Plaintext","w");
  if(plaintextFile==NULL){
      fprintf(stderr,"Could not open the Plaintext File\n");
      return 1;
    } else {
        fwrite(plaintext, (size_t) blockCipher, sizeof(plaintext) -1 , plaintextFile);
      }

  fclose(plaintextFile);

  return 0;
}


/* Verify the ciphertext file using the Public DSA Key then decrypts
   Input : none - Output : (int) Execution control */

int
verifyDSAandDecrypt()
{
  /* Verify the signature */

  unsigned char * cipher = (unsigned char*) readFile("CIT/Ciphertext");

  FILE * publicDSAFile=fopen("KEYS/DSA/pubDSAKey","r");
  if(publicDSAFile==NULL){
      fprintf(stderr,"Could not open Public DSA Key File\n");
      return 1;
      }

  EVP_PKEY * publicDSAKey=PEM_read_PUBKEY(publicDSAFile,NULL,NULL,NULL);
  if (publicDSAKey==NULL){
      fprintf(stderr,"Could not read key from the File");
      ERR_print_errors_fp(stderr);
      return 2;
  }

  int slen2;
  FILE * signatureFile=fopen("SIGN/SignatureFile","r");
  fscanf(signatureFile,"%d",&slen2);
  unsigned char * sig2=malloc(slen2);
  readBin(sig2,slen2,signatureFile);
  fclose(signatureFile);

  EVP_MD_CTX *mdctxdec = NULL;
  if(!(mdctxdec = EVP_MD_CTX_create())){
      fprintf(stderr,"Could not create context\n");
      ERR_print_errors_fp(stderr);
      return 3;
  }

  if(1!=EVP_DigestVerifyInit(mdctxdec,NULL,MDAlgo,NULL,publicDSAKey)){
      fprintf(stderr,"Could not initialize\n");
      ERR_print_errors_fp(stderr);
      return 4;
  }

  if(1!=EVP_DigestVerifyUpdate(mdctxdec,cipher,strlen((const char *)cipher))){
      fprintf(stderr,"Could not verify\n");
      ERR_print_errors_fp(stderr);
      return 5;
  }

  int decrypt;
  if(1==EVP_DigestVerifyFinal(mdctxdec,sig2,slen2)){
      fprintf(stdout,"Successful verification of message.\n");
      decrypt = decryptRSA();
      return decrypt;
  }
  else{
      fprintf(stdout,"UnSuccessful verification of the message");
  }

  return 0;
}
