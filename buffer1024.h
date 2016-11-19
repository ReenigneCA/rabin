#pragma once
#include <openssl/bn.h>
#include <stdint.h>
#include <string.h>

struct Buffer1024 {
public:
    uint8_t values[128];
    void toBN(BIGNUM * dest) const;
    void fromBN(const BIGNUM * src);
    void clear(){
        memset(values,0,sizeof(values));
    }
    void fillRandom(bool paranoid=false);
    int compare(const Buffer1024 &otherBuffer);
    
};

