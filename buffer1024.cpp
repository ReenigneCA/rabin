#include "buffer1024.h"
#include "rabintools.h"
#include <assert.h>
/*
 * licensed under the GPL version 3 see license.txt
 */

void Buffer1024::fromBN(const BIGNUM* src){
    uint32_t len = BN_num_bytes(src);
    if( len == 0){
        clear();
        return;
    }
    Buffer1024 buf;
    if(len < 128) buf.clear();
    BN_bn2bin(src,buf.values+128-len);
    for(uint8_t c=0; c<128; c++) {
        values[c] = buf.values[127-c];
    }
}

void Buffer1024::toBN(BIGNUM *dest) const{
    uint8_t buf[128];
    for(uint8_t c=0; c<128; c++) {
        buf[c] = values[127-c];
    }
    BN_bin2bn(buf,sizeof(buf),dest); 
}

void Buffer1024::fillRandom(bool paranoid){ //fill it with random characters (useful for symmetric key gen or testing)
    int randBytesNeeded = 128;
    int retTester = 0;
    while(randBytesNeeded > 0) {
        if(!paranoid)
            retTester = Rabin1024_getrandom(values+128-randBytesNeeded,randBytesNeeded,0);
        else
            retTester = Rabin1024_getrandom(values+128-randBytesNeeded,randBytesNeeded,GRND_RANDOM);  
        assert(retTester != -1);
        randBytesNeeded -= retTester;
        if(randBytesNeeded > 0)
            sleep(1);            
    }
}

//returns 1 if this buffer is bigger than the other one
//0 if equal
//-1 if less
int Buffer1024::compare(const Buffer1024 &otherVal){
    for(int8_t c=127; c >= 0; c++){
        if(values[c] > otherVal.values[c]) return 1;
        if(values[c] < otherVal.values[c]) return -1;
    }
    return 0;
}
