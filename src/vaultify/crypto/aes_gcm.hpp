#ifndef VAULTIFY_CRYPTO_AES_GCM_HPP
#define VAULTIFY_CRYPTO_AES_GCM_HPP

#include "vaultify/types.hpp" // For Vaultify::byte_vec, Exceptions
#include <memory>             // For std::unique_ptr

// Forward declare OpenSSL context type from global namespace
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

namespace Vaultify::Crypto {

    /**
     * @brief RAII wrapper for OpenSSL's EVP_CIPHER_CTX.
     * Ensures the context is freed automatically.
     */
    struct EvpCipherCtxDeleter {
        void operator()(EVP_CIPHER_CTX* ctx) const;
    };
    using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

    /**
     * @brief Initializes an OpenSSL EVP context for AES-256-GCM operation.
     * @param key The 32-byte AES key.
     * @param nonce The 12-byte nonce (IV).
     * @param encrypt True for encryption, false for decryption.
     * @return A unique_ptr managing the initialized EVP_CIPHER_CTX.
     * @throws InternalError on failure to initialize the context.
     */
    EvpCipherCtxPtr initialize_context(const byte_vec& key, const byte_vec& nonce, bool encrypt);

    /**
     * @brief Provides Associated Data (AAD) to an initialized GCM context.
     * Must be called after initialize_context and before any process_update calls.
     * @param ctx Pointer to the initialized EVP_CIPHER_CTX.
     * @param aad The associated data.
     * @throws InternalError on failure.
     */
    void provide_aad(EVP_CIPHER_CTX* ctx, const byte_vec& aad);

    /**
     * @brief Processes (encrypts or decrypts) a chunk of payload data.
     * @param ctx Pointer to the EVP_CIPHER_CTX (after AAD has been provided).
     * @param chunk Pointer to the input data chunk.
     * @param chunk_len Length of the input data chunk.
     * @param encrypt True if encrypting, false if decrypting.
     * @return A byte vector containing the output (ciphertext or plaintext).
     * @throws InternalError on failure during processing.
     */
    byte_vec process_update(EVP_CIPHER_CTX* ctx, const byte* chunk, size_t chunk_len, bool encrypt);

    /**
     * @brief Finalizes the GCM encryption process.
     * Processes any buffered data and retrieves the authentication tag.
     * @param ctx Pointer to the EVP_CIPHER_CTX.
     * @return The 16-byte authentication tag.
     * @throws InternalError on failure during finalization or tag retrieval.
     */
    byte_vec finalize_encryption(EVP_CIPHER_CTX* ctx);

    /**
     * @brief Finalizes the GCM decryption process and verifies the authentication tag.
     * Processes any buffered data and compares the calculated tag against the expected one.
     * @param ctx Pointer to the EVP_CIPHER_CTX.
     * @param expected_tag The 16-byte tag read from the input file.
     * @return A byte vector containing the final block of plaintext (if any).
     * @throws DecryptionError if the authentication tag does not match.
     * @throws InternalError on other failures during finalization.
     */
    byte_vec finalize_decryption(EVP_CIPHER_CTX* ctx, const byte_vec& expected_tag);

} // namespace Vaultify::Crypto

#endif // VAULTIFY_CRYPTO_AES_GCM_HPP