//
// Created by carlcosinus on 17.06.20.
//

#ifndef BCRYPT_CPY_TEST_CRYPT_BLOWFISH_H
#define BCRYPT_CPY_TEST_CRYPT_BLOWFISH_H


extern int _crypt_output_magic(const char *setting, char *output, int size);
extern char *_crypt_blowfish_rn(const char *key, const char *setting,
                                char *output, int size);
extern char *_crypt_gensalt_blowfish_rn(const char *prefix,
                                        unsigned long count,
                                        const char *input, int size, char *output, int output_size);
#endif //BCRYPT_CPY_TEST_CRYPT_BLOWFISH_H
