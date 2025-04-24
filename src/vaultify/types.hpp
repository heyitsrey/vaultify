#ifndef VAULTIFY_TYPES_HPP
#define VAULTIFY_TYPES_HPP

#include <vector>
#include <string>
#include <stdexcept>
#include <cstdint> // For fixed-width integers

// Forward declarations for global OpenSSL helper functions (defined in main.cpp)
void initialize_openssl();
void cleanup_openssl();

// --- Top-level Vaultify Namespace ---
namespace Vaultify {

    // --- Type Definitions ---
    using byte = unsigned char;
    using byte_vec = std::vector<byte>;

    // --- Constants ---
    namespace Constants { // Nested namespace for constants
        constexpr char MAGIC_BYTES[] = {'V', 'L', 'T', '1'};
        constexpr uint8_t VERSION = 0x01;
        constexpr size_t SALT_LEN = 16;
        constexpr size_t NONCE_LEN = 12; // Recommended for GCM
        constexpr size_t TAG_LEN = 16;   // AES-GCM tag length (128 bits)
        constexpr size_t AES_KEY_LEN = 32; // AES-256 key length (256 bits)
        constexpr size_t PBKDF2_ITERATIONS = 100000;
        constexpr size_t FILE_BUFFER_SIZE = 4096; // Buffer size for streaming I/O

        // File postfixes
        const std::string ENCRYPT_POSTFIX = ".CRYPT";
        // Removed: const std::string DECRYPT_POSTFIX = ".CLEAR";
        const std::string DECRYPT_FALLBACK_EXT = ".DECRYPTED"; // Extension if input doesn't end with .CRYPT

        // Exit codes
        constexpr int EXIT_OK = 0;
        constexpr int EXIT_USAGE_ERROR = 1;
        constexpr int EXIT_IO_ERROR = 2;
        constexpr int EXIT_DECRYPTION_FAILED = 3;
        constexpr int EXIT_INTERNAL_ERROR = 4;
    } // namespace Constants

    // --- Custom Exception Classes ---
    class VaultifyError : public std::runtime_error {
    public:
        VaultifyError(const std::string& msg, int code)
                : std::runtime_error(msg), exit_code(code) {}
        int get_exit_code() const { return exit_code; }
    private:
        int exit_code;
    };

    class UsageError : public VaultifyError {
    public:
        UsageError(const std::string& msg)
                : VaultifyError(msg, Constants::EXIT_USAGE_ERROR) {}
    };

    class IoError : public VaultifyError {
    public:
        IoError(const std::string& msg)
                : VaultifyError(msg, Constants::EXIT_IO_ERROR) {}
    };

    class DecryptionError : public VaultifyError {
    public:
        DecryptionError(const std::string& msg)
                : VaultifyError(msg, Constants::EXIT_DECRYPTION_FAILED) {}
    };

    class InternalError : public VaultifyError {
    public:
        InternalError(const std::string& msg)
                : VaultifyError(msg, Constants::EXIT_INTERNAL_ERROR) {}
    };

} // namespace Vaultify

#endif // VAULTIFY_TYPES_HPP