#pragma once
#include <openssl/bn.h>
#include <stdint.h>

extern "C" void extended_GCD(const BIGNUM *x, const BIGNUM *y, BIGNUM *gcd,BIGNUM *a,BIGNUM *b, BN_CTX *ctx);//ax+by=gcd

struct buffer1024 {
public:
    uint8_t values[128];
    void toBN(BIGNUM * dest) const;
    void fromBN(const BIGNUM * src);
};

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
    int8_t decrypt(const buffer1024 &cipherText, buffer1024 (&arrayOf4Solutions)[4]);
    //returns 1 for success negative error code otherwise
    int8_t encrypt(const buffer1024 &plainText, buffer1024 &cipherText);
    void printDecData();
};

