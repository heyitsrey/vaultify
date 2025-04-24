#ifndef VAULTIFY_CORE_PROCESSOR_HPP
#define VAULTIFY_CORE_PROCESSOR_HPP

#include "vaultify/types.hpp" // For byte_vec, Constants, Exceptions
#include <fstream>            // For stream types

// Forward declarations to reduce include dependencies
namespace Vaultify::IO { class FileHeader; }

namespace Vaultify::Core {

    /**
     * @brief Orchestrates the cryptographic processing of the file payload.
     * Uses Crypto and IO components to perform encryption or decryption streaming.
     */
    class Processor {
    public:
        Processor() = default;

        /**
         * @brief Encrypts the payload from an input stream to an output stream.
         * Assumes the header has already been written to the output stream.
         * Writes the final authentication tag to the output stream.
         * @param in_file Input stream positioned at the start of the plaintext payload.
         * @param out_file Output stream positioned after the written header.
         * @param key The 32-byte AES key.
         * @param header The fully initialized FileHeader object (contains nonce, salt, AAD info).
         * @throws VaultifyError on processing failures.
         */
        void encrypt_payload(std::ifstream& in_file,
                             std::ofstream& out_file,
                             const byte_vec& key,
                             const IO::FileHeader& header);

        /**
         * @brief Decrypts the payload from an input stream to an output stream.
         * Assumes the header has already been read from the input stream.
         * Reads the authentication tag from the end of the input stream and verifies it.
         * @param in_file Input stream positioned at the start of the ciphertext payload (after header).
         * @param out_file Output stream positioned at the start of where plaintext should be written.
         * @param key The 32-byte AES key.
         * @param header The FileHeader object read from the input file (contains nonce, salt, AAD info).
         * @param header_disk_size The exact size of the header as read from disk.
         * @throws VaultifyError on processing or tag verification failures.
         */
        void decrypt_payload(std::ifstream& in_file,
                             std::ofstream& out_file,
                             const byte_vec& key,
                             const IO::FileHeader& header,
                             size_t header_disk_size); // Pass header size for payload calc

    private:
        /**
         * @brief Common streaming loop for both encryption and decryption.
         * Reads chunks from input, processes them using AES-GCM, writes to output.
         * Handles finalization and tag verification/generation.
         * @param in Input stream.
         * @param out Output stream.
         * @param key AES key.
         * @param nonce GCM nonce.
         * @param aad Associated data.
         * @param payload_size Expected size of the payload (for decryption checks), use -1 for encryption.
         * @param encrypt True for encryption, false for decryption.
         * @param expected_tag Pointer to the expected tag (only for decryption), nullptr otherwise.
         * @throws VaultifyError on failures.
         */
        void stream_process(std::ifstream& in, std::ofstream& out,
                            const byte_vec& key, const byte_vec& nonce,
                            const byte_vec& aad, std::streamsize payload_size,
                            bool encrypt, const byte_vec* expected_tag = nullptr);
    };

} // namespace Vaultify::Core

#endif // VAULTIFY_CORE_PROCESSOR_HPP