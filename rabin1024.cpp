/*
 * licensed under the GPL version 3 see license.txt
 * 
 * @author WDavidO <David Oldford> - 
 * My changelog:
 *  04-11-2016 change to c++ basic layout of object for conversion from large main function
 *  06-11-2016 started wrapping everyting into an object. Extracted key generation portion
 *                     wrote random number seeding code and called it liberally wrote a quick test
 *                     function on top of the regular main function.
 *  07-11-2016 Did a little minor cleanup and wrote the encryption code. I diverged from the
 *                    Original as I don't desire a blinding factor for my purposes. This should simplify
 *                    the decryption code greatly but also means I'll be using the Original code as a
 *                    loose guide only and will have to refer to generic descriptions of the algorithm.
 *  18-11-2016 used the extended_GCD from the original along with the description of rabin from
 *                    https://programmingpraxis.com/2011/11/22/rabins-cryptosystem/ to write the decryption 
 *                    code. Now just need a bit of cleanup and some serialization code and the prototype is
 *                    ready. Then turn it into a library add windows getrandom and profit!  
 *  22-11-2016 Wasn't able to get a hold of the author of the original library to ask permission to release
 *                    this one under the GPLv3 so I've cut out the last of his original code and will be
 *                    rewriting the extended_GCD from scratch.
 *
 *
 */
#include "rabin1024.h"
#include <openssl/rand.h>
#include <assert.h>
#include <unistd.h>
#include "rabintools.h"

#define DEBUG

void Rabin1024::commonConstruct() {
    m_a = m_b = NULL;
    m_ctx=BN_CTX_new();
    BN_CTX_start(m_ctx);

}

void Rabin1024::calculateAB() {
    m_a = BN_new();
    m_b = BN_new();
    extendedGCDCoPrime(m_p, m_q, m_a, m_b, m_ctx);
}

void Rabin1024::seedRandom() {
    int retTester=0;
    int randBytesNeeded = 64;//decided to play it safe as we are generating 64 byte primes
    //BN uses urandom vs random if it needs to (and if it's available on the OS,) so we
    //could end up with a reduced search space that could be exploited though
    //anyone who figured it out would probably deserve the private key for their efforts :)
    char randbuf[64];
    do {
        while(randBytesNeeded > 0) {
#ifndef DEBUG
            retTester = Rabin1024_getrandom(randbuf+64-randBytesNeeded,randBytesNeeded,GRND_RANDOM);
#else
            retTester = Rabin1024_getrandom(randbuf+64-randBytesNeeded,randBytesNeeded,0);
#endif
            assert(retTester != -1);
            randBytesNeeded -= retTester;
            if(randBytesNeeded > 0)
                sleep(1);
        }
        RAND_seed(randbuf,64);
    } while(RAND_status() == 0);
}

void Rabin1024::testAndFreeBN(BIGNUM * val) {
    if(val != NULL) BN_free(val);
}

void Rabin1024::genPrime(BIGNUM * P) {
    BIGNUM * three,*four;
    three = BN_new();
    four = BN_new();
    BN_set_word(three,3);
    BN_set_word(four,4);
    int retTester=0;
    seedRandom();
    retTester = BN_generate_prime_ex(P,512,1,four,three,NULL );
    assert(retTester == 1);
    BN_free(three);
    BN_free(four);
}

void Rabin1024::generatePrimes() {
//this must only be called when the object's state is already clear
    m_p = BN_new();
    m_q = BN_new();
    m_n = BN_new();
//need at least 509 sig bits in p and 508 in q
//this means that the highest byte of n will at 
//least be 2 so an encrypted value can always
//shift its highest byte to become lower than
//n and still have a bit set in the highest byte
    do {
        genPrime(m_p);
    } while(BN_num_bits(m_p) < 509);
    do {
        genPrime(m_q);
    } while(BN_cmp(m_p,m_q) == 0 || BN_num_bits(m_q) < 508);

    BN_mul(m_n,m_p,m_q,m_ctx);
}

Rabin1024::~Rabin1024() {
    testAndFreeBN(m_p);
    testAndFreeBN(m_q);
    testAndFreeBN(m_n);
    testAndFreeBN(m_a);
    testAndFreeBN(m_b);
    BN_CTX_end(m_ctx);
    BN_CTX_free(m_ctx);

}


Rabin1024::Rabin1024(const BIGNUM* N) { //create with only encryption capabilities
    commonConstruct();
    m_p = NULL;
    m_q = NULL;
    m_a = m_b = NULL;
    m_n = BN_new();
    BN_copy(m_n,N);
}
//Note the below function copies in values so the passed in values need to be freed externally
Rabin1024::Rabin1024(const BIGNUM* P, const BIGNUM* Q, const BIGNUM* N) { //create with both if n is NULL we'll calculate it
    commonConstruct();
    m_p = BN_new();
    m_q = BN_new();
    m_n = BN_new();
    m_a = m_b = NULL;

    BN_copy(m_p,P);
    BN_copy(m_q,Q);

    if(N != NULL)
        BN_copy(m_n,N);
    else
        BN_mul(m_n,m_p,m_q,m_ctx);


}

Rabin1024::Rabin1024(const BIGNUM* P, const BIGNUM* Q, const BIGNUM* A, const BIGNUM * B, const BIGNUM* N) {   //create with a and b precalculated for speed
    //if a and b are not correct decryption will return
    //incorrect values
    commonConstruct();
    m_p = BN_new();
    m_q = BN_new();
    m_n = BN_new();
    m_a = BN_new();
    m_b = BN_new();

    BN_copy(m_a,A);
    BN_copy(m_b,B);

    BN_copy(m_p,P);
    BN_copy(m_q,Q);

    if(N != NULL)
        BN_copy(m_n,N);
    else
        BN_mul(m_n,m_p,m_q,m_ctx);


}

Rabin1024::Rabin1024() { //no key data so we'll generate them
    commonConstruct();
    generatePrimes();

}
int8_t Rabin1024::decryptBuffer(const Buffer1024 &cipherText, Buffer1024  (&arrayOf4Solutions)[4]) {
    if(m_p == NULL || m_q == NULL)
        return -1;
    if(m_a == NULL || m_b == NULL)
        calculateAB();

    
    BIGNUM * ct = BN_new();
    cipherText.toBN(ct);
    
    
    BIGNUM *r,*s,*pExp,*qExp;
    r = BN_new();
    s = BN_new();
    pExp = BN_new();
    qExp = BN_new();

    BN_copy(pExp,m_p);
    BN_copy(qExp,m_q);
    BN_add_word(pExp,1);
    BN_add_word(qExp,1);
    BN_div_word(pExp,4);
    BN_div_word(qExp,4);

    BN_mod_exp(r, ct, pExp, m_p, m_ctx);
    BN_mod_exp(s, ct, qExp, m_q, m_ctx);

    BIGNUM *x, *y;
    x = BN_new();
    y = BN_new();
    //reusing pExp and qExp for temporary storage.
    //probably a bad idea :) mostly want to cut
    //down on the number of vars I need to remember
    //to free.
    BN_mod_mul(x, m_b, m_q, m_n , m_ctx);
    BN_mod_mul(pExp, x, r, m_n, m_ctx);
    BN_mod_mul(x, m_a, m_p, m_n, m_ctx);
    BN_mod_mul(qExp, x, s, m_n, m_ctx);

    
    BN_mod_add(x, pExp, qExp, m_n, m_ctx);
    BN_mod_sub(y, pExp, qExp, m_n, m_ctx);
    

    arrayOf4Solutions[0].fromBN(x);
    arrayOf4Solutions[1].fromBN(y);
    //printf("possible values:");
    //print_BN_DEC(x);
    //print_BN_DEC(y);
    BN_copy(pExp,x);
    BN_copy(qExp,y);

    
    BN_mod_sub(x, m_n, pExp, m_n, m_ctx);
    BN_mod_sub(y, m_n, qExp, m_n, m_ctx);
    arrayOf4Solutions[2].fromBN(x);
    arrayOf4Solutions[3].fromBN(y);
    //print_BN_DEC(x);
    //print_BN_DEC(y);
    BN_free(x);
    BN_free(y);
    BN_free(r);
    BN_free(s);
    BN_free(pExp);
    BN_free(qExp);
    
    return 1;
    
}

int8_t Rabin1024::decrypt(const Buffer1024 &cipherText, uint8_t (&plainText)[4][127]){
    Buffer1024 buf[4];
    int retVal = decryptBuffer(cipherText,buf);
    for(int i=0; i < 4; i++)
        for(int c=0;c<127;c++)
            plainText[i][c] = buf[i].values[c];
    return retVal;
    
}

int8_t Rabin1024::decryptPat(const Buffer1024 &cipherText, uint8_t (&plainText)[4][112]){
    const char * pattern = "123456789abcdef";
    uint8_t buf[4][127];
    int retVal = decrypt(cipherText,buf);
    uint8_t numPossible = 0;
    for(int c=0; c<4;c++){
        if(strncmp(pattern,(char *)buf[c],15) == 0){
            for(int j=15;j<127;j++)
                plainText[numPossible][j-15] = buf[c][j];
            numPossible += 1;
        }
        
    }
    if(retVal > 0)
        return numPossible;
    
    return retVal;
}

int8_t  Rabin1024::encryptBuffer(const Buffer1024 &plainText, Buffer1024 &cipherText) {
    if(m_n == NULL)
        return -1;
    BIGNUM * pt,* ct;
    cipherText.clear();
    
    

    pt = BN_new();
    ct = BN_new();
    plainText.toBN(pt);
    if(BN_cmp(pt,m_n) != -1)
        return -2;//plaintext must be smaller than n (m_n)
    //printf("n:");
    //print_BN_DEC(m_n);
    
    
    //printf("pt:");
    //print_BN_DEC(pt);
    
    BN_mod_sqr(ct,pt,m_n,m_ctx);// y = x*x mod n using ctx for temp memory
    assert(BN_num_bytes(ct) <= sizeof(cipherText.values));
    cipherText.fromBN(ct);

    //printf("ct:");
    //print_BN_DEC(ct);
    BN_free(pt);
    BN_free(ct);

    return 1;
}

int8_t Rabin1024::encrypt(const uint8_t (&plainText)[127], Buffer1024 &cipherText){
    Buffer1024 buf, n;
    Rabin1024_getrandom(buf.values+127,1,0);
    if(buf.values[127] == 0) buf.values[127] += 1;
    for(int c=0; c<127; c++)
        buf.values[c] = plainText[c];
    n.fromBN(m_n);
    while(buf.compare(n) != -1) {
        assert(buf.values[127] > 0);
        buf.values[127] = buf.values[127] >> 1;
    }
    return encryptBuffer(buf, cipherText);
}

int8_t Rabin1024::encryptPat(const uint8_t (&plainText)[112], Buffer1024 &cipherText){
    uint8_t buf[127];
    const char * pattern = "123456789abcdef";
    for(int c=0;c<15;c++)
        buf[c] = pattern[c];
    for(int c=15;c<127;c++)
        buf[c] = plainText[c-15];
    return encrypt(buf,cipherText);
    
    
}

void Rabin1024::printDecData() {
    print_BN_DEC(m_p);
    printf("\n");
    print_BN_DEC(m_q);
    printf("\n");
    print_BN_DEC(m_n);
    printf("\n");

}

extern "C" void * Rabin1024Create(uint8_t * keyString){
    Rabin1024 * rabin1024;
    if(keyString == NULL){
        rabin1024= new Rabin1024();
        return rabin1024;
    }
    
    return NULL;
    //TODO
    
};

extern "C" void Rabin1024DestroyRabin1024(void * Rabin){
    Rabin1024 * rabin = (Rabin1024*)Rabin;
    if (rabin != NULL)
        delete rabin;
};


//return a pointer to a buffer containing a string that 
//represents the current key (may include public or public and private key information)
//if includeAandB is true these interim values will be included in the string
//to save on calculating them when the string is loaded later
extern "C" uint8_t * Rabin1024GetKeyString(void * Rabin, bool includeAandB){
    Rabin1024 * rabin = (Rabin1024*)Rabin;
    return NULL;
    //TODO
};

//returns 1 on success negative error codes on failure
extern "C" int8_t Rabin1024EncryptPat(void * Rabin, const uint8_t (&plainText)[112], uint8_t (&cipherText)[128]){
    Rabin1024 * rabin = (Rabin1024*)Rabin;
    Buffer1024 buf;
    uint8_t retVal = rabin->encryptPat(plainText,buf);
    memcpy(cipherText, buf.values,sizeof(buf.values));
    return retVal;
};

//returns 1 on success negative error codes on failure
extern "C" int8_t Rabin1024Encrypt(void * Rabin, const uint8_t (&plainText)[127], uint8_t (&cipherText)[128]){
    Rabin1024 * rabin = (Rabin1024*)Rabin;
    Buffer1024 buf;
    uint8_t retVal = rabin->encrypt(plainText,buf);
    memcpy(cipherText, buf.values,sizeof(buf.values));
    return retVal;
};

//returns the number of possible decryptions or a negative error code. Will almost always
//return only a single possible decryption.
extern "C" int8_t Rabin1024DecryptPat(void * Rabin, const uint8_t (&cipherText)[128],uint8_t (&plainText)[4][112]){
    Rabin1024 * rabin = (Rabin1024*)Rabin;
    Buffer1024 ct;
    memcpy(ct.values, cipherText,sizeof(ct.values));//yeah this is inefficient but likely meaningless
    return rabin->decryptPat(ct,plainText);
};

//returns the number of possible decryptions or a negative error code. Will almost always
//return only a single possible decryption.
extern "C" int8_t Rabin1024Decrypt(void * Rabin, const uint8_t (&cipherText)[128],uint8_t (&plainText)[4][127]){
    Rabin1024 * rabin = (Rabin1024*)Rabin;
    Buffer1024 ct;
    memcpy(ct.values, cipherText,sizeof(ct.values));//yeah this is inefficient but likely meaningless
    return rabin->decrypt(ct,plainText);
};





