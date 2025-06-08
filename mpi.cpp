//
// Created by rostyslav.romanets on 6/7/2025.
//

#include <iostream>
#include <mpi.h>
#include <openssl/rand.h>

#include "common.h"

int main(int argc, char **argv)
{
    int rank;
    int size;

    MPI_Init(&argc, &argv);

    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    try
    {
        std::vector<unsigned char> data_to_encrypt;
        size_t data_size;

        // Key and IV generation and broadcasting
        unsigned char key[AES_BLOCK_LEN];
        unsigned char iv[AES_IV_LEN];

        if (rank == 0)
        {
            data_to_encrypt = read_file_to_buf("../input.dat");
            data_size = data_to_encrypt.size();

            RAND_bytes(key, sizeof(key));
            RAND_bytes(iv, sizeof(iv));
        }

        MPI_Bcast(key, AES_KEY_LEN, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        MPI_Bcast(iv, AES_IV_LEN, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

        MPI_Bcast(&data_size, sizeof(data_size), MPI_BYTE, 0, MPI_COMM_WORLD);

        int chunk_size = static_cast<int>(data_size) / size;

        std::vector<unsigned char> input_chunk(chunk_size);
        std::vector<unsigned char> output_chunk(chunk_size);

        // Encrypt
        MPI_Scatter(rank == 0 ? data_to_encrypt.data() : nullptr, chunk_size, MPI_UNSIGNED_CHAR,
            input_chunk.data(), chunk_size, MPI_UNSIGNED_CHAR,
            0, MPI_COMM_WORLD);

        MPI_Barrier(MPI_COMM_WORLD);

        double start_encryption_time = MPI_Wtime();

        unsigned char iv_for_rank[AES_IV_LEN];
        increment_iv_for_rank(iv, iv_for_rank, rank, chunk_size);
        aes_encrypt_decrypt(input_chunk.data(), output_chunk.data(), chunk_size, key, iv_for_rank, true);

        double end_encryption_time = MPI_Wtime();
        double elapsed_encryption_time = end_encryption_time - start_encryption_time;

        std::vector<unsigned char> encrypted_data;
        if (rank == 0)
        {
            encrypted_data.resize(data_size);
        }

        MPI_Gather(output_chunk.data(), chunk_size, MPI_UNSIGNED_CHAR,
            rank == 0 ? encrypted_data.data() : nullptr, chunk_size, MPI_UNSIGNED_CHAR,
            0, MPI_COMM_WORLD);

        if (rank == 0)
        {
            write_buf_to_file("../encrypted.bin", encrypted_data);
        }

        // Decrypt
        MPI_Scatter(rank == 0 ? encrypted_data.data() : nullptr, chunk_size, MPI_UNSIGNED_CHAR,
            input_chunk.data(), chunk_size, MPI_UNSIGNED_CHAR,
            0, MPI_COMM_WORLD);

        MPI_Barrier(MPI_COMM_WORLD);
        double start_decryption_time = MPI_Wtime();

        increment_iv_for_rank(iv, iv_for_rank, rank, chunk_size);
        aes_encrypt_decrypt(input_chunk.data(), output_chunk.data(), chunk_size, key, iv_for_rank, false);

        double end_decryption_time = MPI_Wtime();
        double elapsed_decryption_time = end_decryption_time - start_decryption_time;

        std::vector<unsigned char> decrypted_data;
        if (rank == 0)
        {
            decrypted_data.resize(data_size);
        }

        MPI_Gather(output_chunk.data(), chunk_size, MPI_UNSIGNED_CHAR,
            rank == 0 ? decrypted_data.data() : nullptr, chunk_size, MPI_UNSIGNED_CHAR,
            0, MPI_COMM_WORLD);

        if (rank == 0)
        {
            write_buf_to_file("../decrypted.bin", decrypted_data);

            // Roundtrip check
            if (std::memcmp(data_to_encrypt.data(), decrypted_data.data(), data_size) == 0) {
                std::cout << "ROUNDTRIP SUCCESS: data matches" << std::endl;
            } else {
                std::cout << "ROUNDTRIP FAILURE: data does not match!" << std::endl;
            }

            std::cout << "Encryption time: " << elapsed_encryption_time << " seconds" << std::endl;
            std::cout << "Decryption time: " << elapsed_decryption_time << " seconds" << std::endl;
        }
    } catch (const std::exception& ex)
    {
        std::cerr << "ERROR in rank " << rank << ": " << ex.what() << std::endl;
    }

    MPI_Finalize();
}

