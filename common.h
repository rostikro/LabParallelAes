//
// Created by rostyslav.romanets on 6/8/2025.
//

#ifndef COMMON_H
#define COMMON_H

#define AES_KEY_LEN 32
#define AES_IV_LEN 16
#define AES_BLOCK_LEN 16

#include <string>
#include <vector>

void increment_iv_for_rank(const unsigned char *iv, unsigned char *iv_out, int rank, int chunk_size);

void aes_encrypt_decrypt(const unsigned char *in,
                 unsigned char *out,
                 int len,
                 const unsigned char *key,
                 const unsigned char *iv,
                 int enc);

std::vector<unsigned char> read_file_to_buf(const std::string& filename);

void write_buf_to_file(const std::string& filename, const std::vector<unsigned char>& buffer);

#endif //COMMON_H
