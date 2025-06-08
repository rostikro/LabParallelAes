//
// Created by rostyslav.romanets on 6/8/2025.
//

#include <chrono>
#include <iostream>
#include <vector>
#include <openssl/rand.h>

#include "common.h"

int main(int argc, char **argv)
{
    try
    {
        std::vector<unsigned char> data_to_encrypt = read_file_to_buf("../input.dat");

        // Key and IV generation
        unsigned char key[AES_BLOCK_LEN];
        unsigned char iv[AES_IV_LEN];

        RAND_bytes(key, sizeof(key));
        RAND_bytes(iv, sizeof(iv));

        std::vector<unsigned char> encrypted_data(data_to_encrypt.size());

        auto start_enc = std::chrono::high_resolution_clock::now();

        aes_encrypt_decrypt(data_to_encrypt.data(), encrypted_data.data(), data_to_encrypt.size(), key, iv, true);

        auto end_enc = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed_enc = end_enc - start_enc;

        write_buf_to_file("../encrypted.bin", encrypted_data);

        std::vector<unsigned char> decrypted_data(data_to_encrypt.size());

        auto start_dec = std::chrono::high_resolution_clock::now();

        aes_encrypt_decrypt(encrypted_data.data(), decrypted_data.data(), data_to_encrypt.size(), key, iv, false);

        auto end_dec = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed_dec = end_dec - start_dec;

        write_buf_to_file("../decrypted.bin", decrypted_data);

        // Roundtrip check
        if (std::memcmp(data_to_encrypt.data(), decrypted_data.data(), data_to_encrypt.size()) == 0) {
            std::cout << "ROUNDTRIP SUCCESS: data matches" << std::endl;
        } else {
            std::cout << "ROUNDTRIP FAILURE: data does not match!" << std::endl;
        }

        std::cout << "Encryption time: " << elapsed_enc.count() << " seconds" << std::endl;
        std::cout << "Decryption time: " << elapsed_dec.count() << " seconds" << std::endl;
    } catch (const std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }
}
