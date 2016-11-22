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

/*
 * I wasn't able to get a hold of the author of the original rabin code that I forked so I decided to replace the last of his code
 * in order to allow me to place my code under the GPLv3. As his code used a blinding factor that I have no need for it was actually
 * more complicated to sort through than simply writing a new decryption function from scratch and given the simplicity of Rabin
 * Encryption I coded the encryption function off the top of my head faster than it would have been to adapt the given main function C
 * code to C++. I also significantly changed the way the primes are generated which amounted to a complete from scratch writing of that 
 * portion. So long story short the only code I used until just now from the original rabin.c was the extended_GCD function. I am now switching
 * things up and writing my own extended GCD function which will assume numbers are coprime (which will be the case for Rabin decryption
 * So there is no need to calculate or specify the GCD (it will be 1) 
 *
 * 
 */
extern "C" void extendedGCDCoPrime(const BIGNUM *a, const BIGNUM *b, BIGNUM * x, BIGNUM * y, BN_CTX *ctx){
    
};




void print_BN_DEC(BIGNUM * a) {
    printf("\n%s\n",(BN_bn2dec(a)));

}
