/**
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
 *  18-11-2016 used the extended_GCD from teh original along with the description of rabin from
 *                    https://programmingpraxis.com/2011/11/22/rabins-cryptosystem/ to write the decryption 
 *                    code. Now just need a bit of cleanup and some serialization code and the prototype is
 *                    ready. Then turn it into a library add windows getrandom and profit!  
 *
 * extended_GCD function from: sgangam <Sriharsha Gangam>
 *
 * Compiling instructions:
 * ./build.sh
 *
 * or
 *
 * g++ rabin.cpp -lcrypto
 *
 * Execution:
 * ./a.out
 *
 *
 *
 */
#include "Rabin1024.h"
#include <openssl/rand.h>
#include <assert.h>
#include <unistd.h>
#if defined __gnu_linux__ || defined TARGET__OS_MAC
#include <linux/random.h>
#include <syscall.h>
#include <iostream>
#include <string.h>

#define getrandom(a,b,c) syscall(SYS_getrandom,a,b,c)
#elif
//TODO need to define a crypto secure getrandom function for windows
#endif

extern "C" void extended_GCD(const BIGNUM *a,const BIGNUM *b,BIGNUM *gcd,BIGNUM *x,BIGNUM *y, BN_CTX *ctx)//ax+by=gcd
{

    BIGNUM *x1,*y1,*div,*rem, *temp, *a1,*b1;
    x1=BN_new();
    y1=BN_new();
    div=BN_new();
    rem=BN_new();
    temp=BN_new();
    a1=BN_new();
    b1=BN_new();

    BN_copy(a1,a);
    BN_copy(b1,b);
    BN_set_word(x1,0);
    BN_set_word(x,1);
    BN_set_word(y1,1);
    BN_set_word(y,0);

    while(!BN_is_zero(b1))
    {
        BN_copy(temp,b1);
        BN_div(div,rem,a1,b1,ctx);
        BN_copy(b1,rem);
        BN_copy(a1,temp);

        BN_copy(temp,x1);
        BN_mul(x1,x1,div,ctx);
        BN_sub(x1,x,x1);
        BN_copy(x,temp);

        BN_copy(temp,y1);
        BN_mul(y1,y1,div,ctx);
        BN_sub(y1,y,y1);
        BN_copy(y,temp);
    }
    BN_copy(gcd,a1);
    BN_free(x1);
    BN_free(y1);
    BN_free(a1);
    BN_free(b1);
    BN_free(temp);
    BN_free(div);
    BN_free(rem);
}

void buffer1024::fromBN(const BIGNUM* src){
    uint32_t len = BN_num_bytes(src);
    if( len == 0){
        memset(values,0,sizeof(values));
        return;
    }
    uint8_t buf[128];
    if(len < 128) memset(buf,0,sizeof(buf));
    BN_bn2bin(src,buf+128-len);
    for(uint8_t c=0; c<128; c++) {
        values[c] = buf[127-c];
    }
}

void buffer1024::toBN(BIGNUM *dest) const{
    uint8_t buf[128];
    for(uint8_t c=0; c<128; c++) {
        buf[c] = values[127-c];
    }
    BN_bin2bn(buf,sizeof(buf),dest); 
}


//TODO look at the BN_*_MPI functions yarg kdevelop is really annoying me...
void print_BN_DEC(BIGNUM * a) {
    printf("%s",(BN_bn2dec(a)));

}


void Rabin1024::commonConstruct() {
    m_a = m_b = NULL;
    m_ctx=BN_CTX_new();
    BN_CTX_start(m_ctx);

}

void Rabin1024::calculateAB() {
    BIGNUM * gcd;
    gcd = BN_new();
    m_a = BN_new();
    m_b = BN_new();
    extended_GCD(m_p, m_q,gcd, m_a, m_b, m_ctx);
    BN_free(gcd);
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
            retTester = getrandom(randbuf+64-randBytesNeeded,randBytesNeeded,GRND_RANDOM);
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
        std::cout << BN_num_bits(m_p) << "\n";
    } while(BN_num_bits(m_p) < 509);
    do {
        genPrime(m_q);
        std::cout << BN_num_bits(m_q) << "\n";
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
int8_t Rabin1024::decrypt(const buffer1024 &cipherText, buffer1024  (&arrayOf4Solutions)[4]) {
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
    BN_copy(pExp,x);
    BN_copy(qExp,y);

    
    BN_mod_sub(x, m_n, pExp, m_n, m_ctx);
    BN_mod_sub(y, m_n, qExp, m_n, m_ctx);
    arrayOf4Solutions[2].fromBN(x);
    arrayOf4Solutions[3].fromBN(y);
    BN_free(x);
    BN_free(y);
    BN_free(r);
    BN_free(s);
    BN_free(pExp);
    BN_free(qExp);
    
    
    
}
int8_t  Rabin1024::encrypt(const buffer1024 &plainText, buffer1024 &cipherText) {
    if(m_n == NULL)
        return -1;
    BIGNUM * pt,* ct;
    memset(cipherText.values,0,sizeof(cipherText.values));
    

    pt = BN_new();
    ct = BN_new();
    plainText.toBN(pt);
    BN_mod_sqr(ct,pt,m_n,m_ctx);// y = x*x mod n using ctx for temp memory
    assert(BN_num_bytes(ct) <= sizeof(cipherText.values));
    cipherText.fromBN(ct);
    std::cout << "\nencryption done value:";
    print_BN_DEC(ct);
    std::cout << "\n";
    
    
    BN_free(pt);
    BN_free(ct);

    return 1;
}


void Rabin1024::printDecData() {
    print_BN_DEC(m_p);
    printf("\n");
    print_BN_DEC(m_q);
    printf("\n");
    print_BN_DEC(m_n);
    printf("\n");

}










//This file generates two primes and encrypts a given message.
int main()
{
    uint32_t i, j;

    std::cin >> i;
    std::cout << i << "\n";

    Rabin1024 gusTheTestRabin;
    gusTheTestRabin.printDecData();
    buffer1024 plainText;
    buffer1024 cipherText;
    memset(plainText.values,0,sizeof(plainText.values));
    plainText.values[0] = ((char*)&i)[0];
    plainText.values[1] = ((char*)&i)[1];
    plainText.values[2] = ((char*)&i)[2];
    plainText.values[3] = ((char*)&i)[3];

    gusTheTestRabin.encrypt(plainText, cipherText);
    buffer1024 results[4];
    gusTheTestRabin.decrypt(cipherText,results);
    return 0;


}
