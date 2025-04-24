#ifndef VAULTIFY_CRYPTO_PRIMITIVES_HPP
#define VAULTIFY_CRYPTO_PRIMITIVES_HPP

#include "vaultify/types.hpp" // Vaultify::byte_vec etc.
#include <string>
#include <filesystem> // Keep for path usage if any (currently none here)

namespace Vaultify::Crypto {

    // Securely clear memory
    void secure_zero_memory(void* ptr, size_t len);
    void secure_zero_memory(byte_vec& vec);
    void secure_zero_memory(std::string& str);

    // Generate cryptographically secure random bytes
    byte_vec generate_random_bytes(size_t len);

    // Derive key using PBKDF2-HMAC-SHA256
    byte_vec derive_key_pbkdf2(const std::string& password, const byte_vec& salt);

    // Constant time comparison
    bool constant_time_compare(const byte* a, const byte* b, size_t len);

    // Removed: read_key_from_file function

} // namespace Vaultify::Crypto

#endif // VAULTIFY_CRYPTO_PRIMITIVES_HPP