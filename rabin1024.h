#pragma once
#include "buffer1024.h"
#include <openssl/bn.h>
#include <stdint.h>
#include <string.h>


class Rabin1024 {
private:
    BIGNUM *m_p,*m_q,*m_n,*m_a,*m_b;
    BN_CTX *m_ctx;
    void commonConstruct();
    void generatePrimes();
    void seedRandom();
    void testAndFreeBN(BIGNUM * val);
    void genPrime(BIGNUM * Prime);
    void calculateAB();
public:
    Rabin1024(const BIGNUM* n);//create with only decryption capabilities
    Rabin1024(const BIGNUM* p, const BIGNUM* q, const BIGNUM* n=NULL);//create with both if n is NULL we'll calculate it
    Rabin1024(const BIGNUM* p, const BIGNUM* q, const BIGNUM *A, const BIGNUM *B, const BIGNUM* n=NULL);//if a and b are cached for speed
    Rabin1024();//no key data so we'll generate them
    ~Rabin1024();
    //returns 1 for success negative error code otherwise
    int8_t decryptEx(const Buffer1024 &cipherText, Buffer1024 (&arrayOf4Solutions)[4]);
    int8_t decrypt(const Buffer1024 &cipherText, uint8_t (&plainText)[4][127]);
    //returns 1 for success negative error code otherwise
    //plainText must be smaller than n (m_n) which you can get with getN
    int8_t encryptEx(const Buffer1024 &plainText, Buffer1024 &cipherText);
    //plainText will be padded to 128 bytes properly WRT n (m_n)
    int8_t encrypt(const uint8_t (&plainText)[127], Buffer1024 &cipherText);
    void printDecData();
    void getN(Buffer1024 &dest){ dest.fromBN(m_n);}
};

