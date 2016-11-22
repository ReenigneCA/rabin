/*
 * licensed under the GPL version 3 see license.txt
 */

#include <stdint.h>
#include <stddef.h>

//create a new Rabin1024 key pair from keyString.
//if keyString == NULL a new 1024 bit key pair will be created
extern "C" void * Rabin1024Create(uint8_t * keyString = NULL);

//return a pointer to a buffer containing a string that 
//represents the current key (may include public or public and private key information)
//if includeAandB is true these interim values will be included in the string
//to save on calculating them when the string is loaded later
extern "C" uint8_t * Rabin1024GetKeyString(void * rabin, bool includeAandB=false);

//returns 1 on success negative error codes on failure
extern "C" int8_t Rabin1024Encrypt(void * rabin, const uint8_t (&plainText)[112], uint8_t (&cipherText)[128]);

//returns the number of possible decryptions or a negative error code. Will almost always
//return only a single possible decryption.
extern "C" int8_t Rabin1024Decrypt(void * rabin, const uint8_t (&cipherText)[128],uint8_t (&plainText)[4][112]);

//returns the number of possible decryptions or a negative error code. Will almost always
//return only a single possible decryption.
extern "C" int8_t Rabin1024DecryptPat(void * rabin, const uint8_t (&cipherText)[128],uint8_t (&plainText)[4][112]);

//Release the memory associated with a Rabin1024 object
extern "C" void Rabin1024DestroyRabin1024(void * rabin);
