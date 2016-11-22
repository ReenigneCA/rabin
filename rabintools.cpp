/*
 * licensed under the GPL version 3 see license.txt
 */
#include "rabintools.h"


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
 * Written based on Knuth's the art of computer programming volume 2
 * 
 * After finishing this I decided to add the option of getting the gcd as it comes out anyway if gcd is set to NULL however
 * it will skip copying the value into it. It's a bit ugly having gcd after the ctx but the only way I can make the argument
 * automatically optional without making it a member function of Rabin1024
 *
 * 
 */
extern "C" void extendedGCDCoPrime(const BIGNUM *a, const BIGNUM *b, BIGNUM * x, BIGNUM * y, BN_CTX *ctx, BIGNUM *gcd){
    if(BN_is_zero(b)){
        BN_set_word(x,1);
        BN_set_word(y,0);
        return;
    }
    
    BIGNUM *u1,*u2,*u3,*v1,*v2,*v3,*t1,*t2,*t3,*q,*vtmp, *swap;
    u1 = BN_new();
    u2 = BN_new();
    u3 = BN_new();
        
    v1 = BN_new();
    v2 = BN_new();
    v3 = BN_new();
        
    t1 = BN_new();
    t2 = BN_new();
    t3 = BN_new();
    
    q = BN_new();

    vtmp = BN_new();
    
    BN_set_word(u1,1);
    BN_set_word(u2,0);
    BN_copy(u3,a);
    
    BN_set_word(v1,0);
    BN_set_word(v2,1);

    BN_copy(v3,b);


    while(!BN_is_zero(v3)){
    
    BN_div(q,t3,u3,v3,ctx);

    BN_mul(vtmp,v1,q,ctx);
    BN_sub(t1,u1,vtmp);
    BN_mul(vtmp,v2,q,ctx);
  
    BN_sub(t2,u2,vtmp);

    swap = u1;
    u1 = v1;
    v1 = t1;
    t1 = swap;
    
    swap = u2;
    u2 = v2;
    v2 = t2;
    t2 = swap;
    
    swap = u3;
    u3 = v3;
    v3 = t3;
    t3 = swap;
   
    }

    BN_copy(x,u1);

    BN_copy(y,u2);
    if(gcd != NULL)
        BN_copy(gcd,u3);
    

    BN_free(u1);
    BN_free(u2);
    BN_free(u3);
       
    BN_free(v1);
    BN_free(v2);
    BN_free(v3);
       
    BN_free(t1);
    BN_free(t2);
    BN_free(t3);
    BN_free(q);
    BN_free(vtmp);
};




void print_BN_DEC(BIGNUM * a) {
    printf("\n%s\n",(BN_bn2dec(a)));

}
