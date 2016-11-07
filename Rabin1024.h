#pragma once
#include <openssl/bn.h>
#include <stdint.h>

extern "C" void extended_GCD(BIGNUM *x, BIGNUM *y,BIGNUM *gcd,BIGNUM *a,BIGNUM *b);//ax+by=gcd

struct buffer1024{
    uint8_t values[128];
};

class Rabin1024{
private:
    BIGNUM* p,*q,*n;
    BN_CTX *ctx;
    void commonConstruct();
    void generatePrimes();
    void seedRandom();
    void testAndFreeBN(BIGNUM * val);
    void genPrime(BIGNUM * Prime);
public:
    Rabin1024(BIGNUM* n);//create with only decryption capabilities
    Rabin1024(BIGNUM* p, BIGNUM* q,BIGNUM* n=NULL);//create with both if n is NULL we'll calculate it
    Rabin1024();//no key data so we'll generate them
    ~Rabin1024();
    //returns 1 for success negative error code otherwise
    int8_t decrypt(buffer1024 * cipherText, buffer1024 * arrayOf4Solutions);
    //returns 1 for success negative error code otherwise
    int8_t encrypt(buffer1024 * plainText, buffer1024* cipherText);
    void printDecData();
};

