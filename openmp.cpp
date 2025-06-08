//
// Created by rostyslav.romanets on 6/8/2025.
//

#include <iostream>
#include <vector>
#include <openssl/rand.h>
#include <omp.h>

#include "common.h"

double encrypt_decrypt_parallel(
    size_t chunk_size,
    size_t remainder,
    int num_of_threads,
    const unsigned char* iv,
    const unsigned char* key,
    const std::vector<unsigned char>& in,
    std::vector<unsigned char>& out,
    bool enc)
{
    double start = omp_get_wtime();

#pragma omp parallel
    {
        int thread_id = omp_get_thread_num();

        size_t start_offset = thread_id * chunk_size;
        size_t chunk_size_for_this_threads = chunk_size;

        if (thread_id == num_of_threads - 1)
        {
            chunk_size_for_this_threads += remainder;
        }

        unsigned char iv_for_this_thread[AES_IV_LEN];
        increment_iv_for_rank(iv, iv_for_this_thread, thread_id, chunk_size_for_this_threads);

        aes_encrypt_decrypt(in.data() + start_offset, out.data() + start_offset,
            chunk_size_for_this_threads, key, iv_for_this_thread, enc);
    }

    double end = omp_get_wtime();
    double elapsed = end - start;

    return elapsed;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        std::cout << "Usage: " << argv[0] << " <num_of_threads>" << std::endl;
        return 1;
    }

    int num_of_threads = atoi(argv[1]);

    try
    {
        std::vector<unsigned char> data_to_encrypt = read_file_to_buf("../input.dat");

        // Key and IV generation
        unsigned char key[AES_BLOCK_LEN];
        unsigned char iv[AES_IV_LEN];

        RAND_bytes(key, sizeof(key));
        RAND_bytes(iv, sizeof(iv));

        std::vector<unsigned char> encrypted_data(data_to_encrypt.size());
        std::vector<unsigned char> decrypted_data(data_to_encrypt.size());

        omp_set_num_threads(num_of_threads);

        size_t chunk_size = data_to_encrypt.size() / num_of_threads;
        size_t remainder = data_to_encrypt.size() % num_of_threads;

        // Encrypt
        auto elapsed_enc = encrypt_decrypt_parallel(chunk_size, remainder, num_of_threads, iv, key, data_to_encrypt, encrypted_data, true);

        write_buf_to_file("../encrypted.bin", encrypted_data);

        // Decrypt
        auto elapsed_dec = encrypt_decrypt_parallel(chunk_size, remainder, num_of_threads, iv, key, encrypted_data, decrypted_data, false);

        write_buf_to_file("../decrypted.bin", decrypted_data);

        if (std::memcmp(data_to_encrypt.data(), decrypted_data.data(), data_to_encrypt.size()) == 0)
        {
            std::cout << "ROUNDTRIP SUCCESS: data matches" << std::endl;
        }
        else
        {
            std::cout << "ROUNDTRIP FAILURE: data does not match!" << std::endl;
        }

        std::cout << "Encryption time: " << elapsed_enc << " seconds" << std::endl;
        std::cout << "Decryption time: " << elapsed_dec << " seconds" << std::endl;
    } catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }
}
