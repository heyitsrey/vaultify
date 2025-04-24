#include "aes_gcm.hpp"
#include "primitives.hpp" // For secure_zero_memory
#include "vaultify/types.hpp"

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/err.h>

#include <vector> // std::vector used for buffers

namespace Vaultify::Crypto {

    // --- EvpCipherCtxDeleter Implementation ---
    void EvpCipherCtxDeleter::operator()(EVP_CIPHER_CTX* ctx) const {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }

    // --- Public Function Implementations ---

    EvpCipherCtxPtr initialize_context(const byte_vec& key, const byte_vec& nonce, bool encrypt) {
        using namespace Vaultify::Constants; // Access constants easily
        if (key.size() != AES_KEY_LEN) throw InternalError("AES GCM: Invalid key size for context initialization (" + std::to_string(key.size()) + ").");
        if (nonce.size() != NONCE_LEN) throw InternalError("AES GCM: Invalid nonce size for context initialization (" + std::to_string(nonce.size()) + ").");

        EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) throw InternalError("AES GCM: Failed to create EVP_CIPHER_CTX.");

        const EVP_CIPHER* cipher = EVP_aes_256_gcm();
        if (!cipher) throw InternalError("AES GCM: Failed to get EVP_aes_256_gcm cipher.");

        int init_result = 0;
        unsigned long err_code;

        // 1. Initialize cipher type
        if (encrypt) {
            init_result = EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr);
        } else {
            init_result = EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr);
        }
        if (init_result != 1) {
            err_code = ERR_get_error();
            throw InternalError("AES GCM: Failed to initialize context (EVP_*Init_ex step 1). Error: " + std::string(ERR_error_string(err_code, nullptr)));
        }

        // 2. Set IV length (GCM specific)
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) != 1) {
            err_code = ERR_get_error();
            throw InternalError("AES GCM: Failed to set GCM nonce length (EVP_CTRL_GCM_SET_IVLEN). Error: " + std::string(ERR_error_string(err_code, nullptr)));
        }

        // 3. Set key and IV (nonce)
        if (encrypt) {
            init_result = EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data());
        } else {
            init_result = EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data());
        }
        if (init_result != 1) {
            err_code = ERR_get_error();
            throw InternalError("AES GCM: Failed to set key and nonce (EVP_*Init_ex step 3). Error: " + std::string(ERR_error_string(err_code, nullptr)));
        }

        return ctx; // Transfer ownership via unique_ptr
    }

    void provide_aad(EVP_CIPHER_CTX* ctx, const byte_vec& aad) {
        if (!ctx) throw InternalError("AES GCM: provide_aad called with null context.");
        if (aad.empty()) return; // Nothing to do if AAD is empty

        int out_len_ignore = 0; // Output length is not relevant for AAD-only update
        // Use EncryptUpdate for both encrypt/decrypt when providing only AAD
        if (EVP_EncryptUpdate(ctx, nullptr, &out_len_ignore, aad.data(), static_cast<int>(aad.size())) != 1) {
            unsigned long err_code = ERR_get_error();
            // This could fail during decryption if header was tampered, treat as internal error here, tag check is main guard
            throw InternalError("AES GCM: Failed to provide AAD to context (EVP_EncryptUpdate for AAD). Error: " + std::string(ERR_error_string(err_code, nullptr)));
        }
    }

    byte_vec process_update(EVP_CIPHER_CTX* ctx, const byte* chunk, size_t chunk_len, bool encrypt) {
        if (!ctx) throw InternalError("AES GCM: process_update called with null context.");
        if (!chunk && chunk_len > 0) throw InternalError("AES GCM: process_update called with null chunk pointer but non-zero length.");
        if (chunk_len == 0) return {}; // Nothing to process

        // Output buffer needs space for input + one block overhead
        size_t out_buf_size = chunk_len + EVP_MAX_BLOCK_LENGTH;
        byte_vec out_buffer(out_buf_size);
        int out_len = 0; // Actual output length written by EVP_*Update

        int update_result = 0;
        unsigned long err_code;

        if (encrypt) {
            update_result = EVP_EncryptUpdate(ctx, out_buffer.data(), &out_len, chunk, static_cast<int>(chunk_len));
        } else {
            update_result = EVP_DecryptUpdate(ctx, out_buffer.data(), &out_len, chunk, static_cast<int>(chunk_len));
        }

        if (update_result != 1) {
            err_code = ERR_get_error();
            throw InternalError(std::string("AES GCM: Failed during processing payload (EVP_") + (encrypt ? "Encrypt" : "Decrypt") + "Update). Error: " + std::string(ERR_error_string(err_code, nullptr)));
        }

        // Resize output buffer to actual size
        out_buffer.resize(static_cast<size_t>(out_len));
        return out_buffer;
    }

    byte_vec finalize_encryption(EVP_CIPHER_CTX* ctx) {
        if (!ctx) throw InternalError("AES GCM: finalize_encryption called with null context.");

        // Buffer for any final block data (usually empty for GCM unless partial block processed)
        byte_vec final_block_buffer(EVP_MAX_BLOCK_LENGTH);
        int final_len = 0;
        unsigned long err_code;

        // 1. Finalize encryption processing
        if (EVP_EncryptFinal_ex(ctx, final_block_buffer.data(), &final_len) != 1) {
            err_code = ERR_get_error();
            throw InternalError("AES GCM: Encryption finalization failed (EVP_EncryptFinal_ex). Error: " + std::string(ERR_error_string(err_code, nullptr)));
        }
        // Note: final_len is often 0 for GCM, but handle potential output just in case.
        // This output should have been written by the caller if process_update returned it.
        // The main purpose here is step 2.

        // 2. Get the authentication tag
        byte_vec tag(Vaultify::Constants::TAG_LEN);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, Vaultify::Constants::TAG_LEN, tag.data()) != 1) {
            err_code = ERR_get_error();
            throw InternalError("AES GCM: Failed to get authentication tag (EVP_CTRL_GCM_GET_TAG). Error: " + std::string(ERR_error_string(err_code, nullptr)));
        }

        return tag;
    }

    byte_vec finalize_decryption(EVP_CIPHER_CTX* ctx, const byte_vec& expected_tag) {
        using namespace Vaultify::Constants;
        if (!ctx) throw InternalError("AES GCM: finalize_decryption called with null context.");
        if (expected_tag.size() != TAG_LEN) {
            throw InternalError("AES GCM: Invalid expected tag size (" + std::to_string(expected_tag.size()) + ") provided to finalize_decryption.");
        }

        unsigned long err_code;

        // 1. Set the expected tag *before* calling final
        // Need a non-const pointer for the OpenSSL API call. Create a temporary copy.
        byte_vec mutable_tag = expected_tag;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, mutable_tag.data()) != 1) {
            err_code = ERR_get_error();
            secure_zero_memory(mutable_tag); // Clear copy
            throw InternalError("AES GCM: Failed to set expected authentication tag (EVP_CTRL_GCM_SET_TAG). Error: " + std::string(ERR_error_string(err_code, nullptr)));
        }
        secure_zero_memory(mutable_tag); // Clear copy after setting

        // 2. Call final to process last block AND verify tag
        byte_vec final_block_buffer(EVP_MAX_BLOCK_LENGTH);
        int final_len = 0;

        // EVP_DecryptFinal_ex returns 1 for success (tag OK), 0 for failure (tag mismatch), < 0 other errors.
        int finalize_result = EVP_DecryptFinal_ex(ctx, final_block_buffer.data(), &final_len);

        if (finalize_result > 0) {
            // Success! Tag matched. Return any final plaintext block.
            final_block_buffer.resize(static_cast<size_t>(final_len));
            return final_block_buffer;
        } else if (finalize_result == 0) {
            // Tag verification failed! Clear potentially sensitive buffer contents.
            secure_zero_memory(final_block_buffer);
            throw DecryptionError("Decryption failed: Authentication tag mismatch. File may be corrupt or the key/password is incorrect.");
        } else {
            // Other OpenSSL error during finalization. Clear buffer.
            err_code = ERR_get_error();
            secure_zero_memory(final_block_buffer);
            throw InternalError("AES GCM: Decryption finalization failed (EVP_DecryptFinal_ex). Error: " + std::string(ERR_error_string(err_code, nullptr)));
        }
    }

} // namespace Vaultify::Crypto