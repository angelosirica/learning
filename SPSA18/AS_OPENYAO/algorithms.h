#ifndef _DS2

#define blockCipher EVP_aes_256_cbc()           /* block cipher for hybrid encryption */
#define MDAlgo EVP_sha256()                     /* hash algorithm for signatures */
#define armorAlgo EVP_aes_256_cbc()             /* armor algorithm for storing private keys */

static char passphrase[]="forzaNapoli";                /* pass phrase for storing private keys */
#define filename "../YAO/Circuits/garCirc-000-000.txt"

#define OSKEYLEN 2048                               /* lenght of asymmetric keys */

#define _DS2

#endif
