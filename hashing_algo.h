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

/* Wrapper for newer openssl digest interfaces taken from
 * lighttpd sys-crypto-md.h - message digest (MD) wrapper
 *
 * Copyright(c) 2020 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 *
 * https://www.lighttpd.net/
 */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/evp.h>

#define MD5_CTX EVP_MD5_CTX
#define MD5_Init EVP_MD5_Init
#define MD5_Final EVP_MD5_Final
#define MD5_Update EVP_MD5_Update

typedef EVP_MD_CTX * EVP_MD5_CTX;

static inline int
EVP_MD5_Init(EVP_MD5_CTX *ctx)
{
    return ((*ctx = EVP_MD_CTX_new()) != NULL
            && 1 == EVP_DigestInit_ex(*ctx, EVP_md5(), NULL));
}

static inline int
EVP_MD5_Final(unsigned char *digest, EVP_MD5_CTX *ctx)
{
    /* MD5_DIGEST_LENGTH; EVP_MD_size(EVP_md5()) */
    int rc = EVP_DigestFinal_ex(*ctx, digest, NULL);
    EVP_MD_CTX_free(*ctx);
    return (1 == rc);
}

static inline int
EVP_MD5_Update(EVP_MD5_CTX *ctx, const void *data, size_t length)
{
    return (1 == EVP_DigestUpdate(*ctx, data, length));
}

#endif

/* end of code from lighttpd */

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

