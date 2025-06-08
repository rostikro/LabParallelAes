//
// Created by rostyslav.romanets on 6/8/2025.
//

#include "common.h"

#include <cstring>
#include <fstream>
#include <iosfwd>
#include <vector>
#include <openssl/evp.h>

void increment_iv_for_rank(const unsigned char *iv, unsigned char *iv_out, int rank, int chunk_size)
{
    memcpy(iv_out, iv, AES_IV_LEN);

    const unsigned long long block_offset = static_cast<unsigned long long>(chunk_size) / AES_BLOCK_LEN * rank;

    auto *counter = reinterpret_cast<unsigned long long*>(iv_out + AES_IV_LEN - 8);
    *counter = *counter + block_offset;
}

void aes_encrypt_decrypt(const unsigned char *in,
                 unsigned char *out,
                 const int len,
                 const unsigned char *key,
                 const unsigned char *iv,
                 const int enc)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len = 0;
    int total_len = 0;

    EVP_CipherInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv, enc);

    EVP_CipherUpdate(ctx, out, &out_len, in, len);
    total_len += out_len;

    EVP_CipherFinal_ex(ctx, out + total_len, &out_len);

    EVP_CIPHER_CTX_free(ctx);
}

std::vector<unsigned char> read_file_to_buf(const std::string& filename)
{
    std::ifstream file(filename, std::ios::binary);

    if (!file)
    {
        throw std::runtime_error("File could not be opened");
    }

    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);

    if (!file.read(reinterpret_cast<char *>(buffer.data()), size))
    {
        throw std::runtime_error("File could not be read");
    }

    return buffer;
}

void write_buf_to_file(const std::string& filename, const std::vector<unsigned char>& buffer)
{
    std::ofstream file(filename, std::ios::binary);

    if (!file)
    {
        throw std::runtime_error("File could not be opened");
    }

    file.write(reinterpret_cast<const char *>(buffer.data()), buffer.size());
}
