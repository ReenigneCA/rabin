/*
 * licensed under the GPL version 3 see license.txt
 */
#include "rabin1024.h"
#include <iostream>
#include <string.h>
#include <assert.h>
#include "rabintools.h"

int main()
{
//     BIGNUM * a, *b,*x,*y;
//     BN_CTX * ctx;
//     ctx=BN_CTX_new();
//     
//     a = BN_new();
//     b = BN_new();
//     x = BN_new();
//     y = BN_new();
//     BN_set_word(a,17);
//     BN_set_word(b,7);
//     extendedGCDCoPrime(a,b,x,y,ctx);
//     print_BN_DEC(x);
//     print_BN_DEC(y);
//     
//     return 0;
    Rabin1024 *gusTheTestRabin;
    //gusTheTestRabin.printDecData();
    uint8_t plainText[112];
    Buffer1024 cipherText;
    uint8_t results[4][112];
    uint8_t numPossible;
    int pauseint;
    

    for(int j =0; j < 10000; j++) {
        gusTheTestRabin = new Rabin1024();
        //gusTheTestRabin->printDecData();
        bool resultsWorked;

        for(int c = 0; c < 10000; c++) {
            resultsWorked = false;
            Rabin1024_getrandom(plainText,112,0);
            gusTheTestRabin->encryptPat(plainText, cipherText);
            numPossible = gusTheTestRabin->decryptPat(cipherText,results);
            assert(numPossible > 0);
            if(numPossible > 1){
                std::cout << "\nWow this is unlikely enter a number to continue\n";
                std::cin >> pauseint;
            }
            for(int i=0; i <numPossible; i++) {
                if(strncmp((char*)plainText,(char*)results[i],112) == 0) {
                    resultsWorked = true;
                    break;
                }
            }
            assert(resultsWorked);
            if(c % 100 == 0)
                std::cout << "c="<< c << "\n";
        }
        delete gusTheTestRabin;
        std::cout << "j="<< j << "\n";
    }


    return 0;


}
