/*
 * licensed under the GPL version 3 see license.txt
 */
#pragma once
#include <openssl/bn.h>

#if defined __gnu_linux__ || defined TARGET__OS_MAC
#include <linux/random.h>
#include <syscall.h>
#include <unistd.h>
#if defined SYS_getrandom
#define Rabin1024_getrandom(a,b,c) syscall(SYS_getrandom,a,b,c)
#else
//old linux kernel
#define GRND_RANDOM 1
#include <fcntl.h>
#include <assert.h>
int Rabin1024_getrandom(void* buffer,uint b,uint c);
#endif
#else
#define GRND_RANDOM 1
int Rabin1024_getrandom(void* buffer,uint b,uint c);
#endif
extern "C" void extendedGCDCoPrime(const BIGNUM *a, const BIGNUM *b, BIGNUM * x, BIGNUM * y, BN_CTX *ctx, BIGNUM *gcd=NULL);
void print_BN_DEC(BIGNUM * a);
