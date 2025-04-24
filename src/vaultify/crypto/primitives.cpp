#include "primitives.hpp"
#include "vaultify/types.hpp" // Provides Vaultify::Constants and Vaultify exceptions

// OpenSSL headers
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/crypto.h> // For CRYPTO_memcmp, OPENSSL_cleanse

#include <fstream>
#include <stdexcept>
#include <iostream> // Removed include, not needed anymore here

namespace Vaultify::Crypto {

    // Internal Helper read_exact_bytes removed as it was only used by read_key_from_file

    // --- Public Function Implementations ---

    void secure_zero_memory(void* ptr, size_t len) {
        if (ptr && len > 0) {
            OPENSSL_cleanse(ptr, len);
        }
    }

    void secure_zero_memory(byte_vec& vec) {
        if (!vec.empty()) {
            OPENSSL_cleanse(vec.data(), vec.size());
        }
        vec.clear();
        vec.shrink_to_fit(); // Attempt to release memory
    }

    void secure_zero_memory(std::string& str) {
        if (!str.empty()) {
            OPENSSL_cleanse(&str[0], str.size());
        }
        str.clear();
        str.shrink_to_fit();
    }


    byte_vec generate_random_bytes(size_t len) {
        if (len == 0) return {}; // Handle edge case
        byte_vec bytes(len);
        if (RAND_bytes(bytes.data(), static_cast<int>(len)) != 1) {
            unsigned long err_code = ERR_get_error();
            throw InternalError("Failed to generate random bytes (OpenSSL RAND_bytes failed). Error: " +
                                std::string(ERR_error_string(err_code, nullptr)));
        }
        return bytes;
    }

    byte_vec derive_key_pbkdf2(const std::string& password, const byte_vec& salt) {
        using namespace Vaultify::Constants;

        if (salt.size() != SALT_LEN) {
            throw InternalError("PBKDF2 internal error: Incorrect salt length provided (" +
                                std::to_string(salt.size()) + " vs " +
                                std::to_string(SALT_LEN) + ").");
        }
        if (password.empty()) {
            throw UsageError("Password cannot be empty for key derivation.");
        }

        byte_vec key(AES_KEY_LEN);
        int result = PKCS5_PBKDF2_HMAC(
                password.c_str(),
                static_cast<int>(password.length()),
                salt.data(),
                static_cast<int>(salt.size()),
                PBKDF2_ITERATIONS,
                EVP_sha256(), // Use SHA-256
                static_cast<int>(key.size()),
                key.data()
        );

        if (result != 1) {
            unsigned long err_code = ERR_get_error();
            throw InternalError("Failed to derive key using PBKDF2 (PKCS5_PBKDF2_HMAC failed). Error: " +
                                std::string(ERR_error_string(err_code, nullptr)));
        }
        return key;
    }

    // Removed: read_key_from_file implementation

    bool constant_time_compare(const byte* a, const byte* b, size_t len) {
        if (!a || !b || len == 0) {
            return false;
        }
        return CRYPTO_memcmp(a, b, len) == 0;
    }

} // namespace Vaultify::Crypto