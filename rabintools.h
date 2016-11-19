#pragma once
#include <openssl/bn.h>

#if defined __gnu_linux__ || defined TARGET__OS_MAC
#include <linux/random.h>
#include <syscall.h>
#include <unistd.h>
#if defined SYS_getrandom
#define Rabin1024_getrandom(a,b,c) syscall(SYS_getrandom,a,b,c)
#else
//TODO linux old kernel
#define Rabin1024_getrandom(a,b,c) \
    if(c == 0)\
        int Rabin1024_randomFD = open("/dev/urandom", 0_RDONLY);\
    else\
        int Rabin1024_randomFD = open("/dev/random", 0_RDONLY);\
    size_t Rabin1024_randomBytesRead = 0;\
    while(Rabin1024_randomBytesRead < b){\
        size_t result = read(Rabin1024_randomFD, a + Rabin1024_randomBytesRead, b - Rabin1024_randomBytesRead);\
        assert(result > 0);\
        Rabin1024_randomBytesRead += result;\
    }\
    close(Rabin1024_randomFD);
#endif
#else
//TODO need to define a crypto secure getrandom function for windows
#endif

extern "C" void extended_GCD(const BIGNUM *x, const BIGNUM *y, BIGNUM *gcd,BIGNUM *a,BIGNUM *b, BN_CTX *ctx);//ax+by=gcd
void print_BN_DEC(BIGNUM * a);
