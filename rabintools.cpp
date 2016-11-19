//* extended_GCD function from: sgangam <Sriharsha Gangam>
#include "rabintools.h"
#include <iostream>

#if defined __gnu_linux__ || defined TARGET__OS_MAC
#if not defined SYS_getrandom
int Rabin1024_getrandom(void* buffer,uint b,uint c) {
    char* a = (char*)buffer;
    int Rabin1024_randomFD;
    if(c == 0) {
        Rabin1024_randomFD = open("/dev/urandom", O_RDONLY);
    }
    else {
        Rabin1024_randomFD = open("/dev/random", O_RDONLY);
    }
    size_t Rabin1024_randomBytesRead = 0;
    while(Rabin1024_randomBytesRead < b) {
        size_t result = read(Rabin1024_randomFD, a + Rabin1024_randomBytesRead, b - Rabin1024_randomBytesRead);
        assert(result > 0);
        Rabin1024_randomBytesRead += result;
    }
    close(Rabin1024_randomFD);
    return b;
}
#endif
#endif
#if not defined __gnu_linux__ && not defined TARGET__OS_MAC
int Rabin1024_getrandom(void* buffer,uint b,uint c) {
    //TODO windows code
}
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


void print_BN_DEC(BIGNUM * a) {
    printf("\n%s\n",(BN_bn2dec(a)));

}
