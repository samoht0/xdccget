/* 
 * File:   hashing_algo.h
 * Author: TBD
 *
 * Created on 13. Januar 2015, 20:30
 */

#ifndef HASHING_ALGO_H
#define	HASHING_ALGO_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <openssl/md5.h>

    enum HashTypes {
        HashType_MD5
    };

    typedef char* (*hash_toString_fct)(unsigned char* hash);
    typedef int (*hash_equals_fct)(unsigned char hash1[], unsigned char hash2[]);
    typedef int (*hash_init_fct)(MD5_CTX *ctx);
    typedef int (*hash_update_fct)(MD5_CTX *ctx, const void *data, size_t len);
    typedef int (*hash_final_fct)(unsigned char *md, MD5_CTX *ctx);
    typedef int (*hash_len)(void *ctx);

    struct HashAlgorithm {
        enum HashTypes hashType;
        MD5_CTX *ctx;
        unsigned int hashSize;
        hash_equals_fct equals;
        hash_init_fct init;
        hash_update_fct update;
        hash_final_fct final;
    };

    typedef struct HashAlgorithm HashAlgorithm;

    HashAlgorithm* createHashAlgorithm(char *hashAlgorithm);
    void freeHashAlgo(HashAlgorithm *algo);

    void getHashFromFile(HashAlgorithm *algo, char *filename, unsigned char *hash);
    void getHashFromString(HashAlgorithm *algo, char *string, unsigned char *hash);
    void getHashFromStringIter(HashAlgorithm *algo, char *string, unsigned char *hash, int numIterations);
    unsigned char* convertHashStringToBinary(HashAlgorithm *algo, char *hashString);

#ifdef	__cplusplus
}
#endif

#endif	/* HASHING_ALGO_H */

