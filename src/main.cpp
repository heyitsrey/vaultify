#include "vaultify/ui/application.hpp" // The application class
#include "vaultify/types.hpp"        // For Constants & OpenSSL helper declarations

// Required OpenSSL includes for init/cleanup functions
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h> // For OPENSSL_config if used

#include <iostream>     // std::cerr, std::cout
#include <exception>    // std::exception

// --- OpenSSL Initialization/Cleanup (Global Scope) ---
// These functions manage global OpenSSL state. Best practice is to call them
// once at the very start and end of the program.

void initialize_openssl() {
    // Load human-readable error strings for ERR_error_string
    // ERR_load_crypto_strings() is deprecated in OpenSSL 1.1.0+, but harmless.
    // OpenSSL 3+ loads them automatically when needed.
    ERR_load_crypto_strings();

    // Register all available digests and ciphers.
    // OpenSSL_add_all_algorithms() is deprecated in OpenSSL 1.1.0+, but harmless.
    // OpenSSL 3+ uses providers loaded from config or defaults.
    OpenSSL_add_all_algorithms();

    // Optional: Load an OpenSSL configuration file if needed.
    // Usually not required unless using specific engines or settings.
    // OPENSSL_config(nullptr);

#ifndef NDEBUG // Print only in debug builds
    std::cout << "Debug: OpenSSL initialized." << std::endl;
#endif
}

void cleanup_openssl() {
    // Free resources allocated by OpenSSL_add_all_algorithms.
    // EVP_cleanup() is deprecated in OpenSSL 1.1.0+ and is a no-op.
    EVP_cleanup();

    // Free resources allocated by ERR_load_crypto_strings.
    // ERR_free_strings() is deprecated in OpenSSL 1.1.0+ and is a no-op.
    ERR_free_strings();

    // Optional: Unload configuration modules if OPENSSL_config was used.
    // CONF_modules_unload(1);

#ifndef NDEBUG // Print only in debug builds
    std::cout << "Debug: OpenSSL cleanup routines called." << std::endl;
#endif
}


// --- Main Function ---
int main(int argc, char* argv[]) {
    // --- Command Line Argument Check ---
    if (argc > 1) {
        // Vaultify does not accept command line args, show usage.
        std::cerr << "Vaultify - File Encryption/Decryption Tool (AES-256-GCM)\n";
        std::cerr << "Usage: Run the executable without arguments and follow the prompts.\n";
        std::cerr << "Command-line arguments are not supported.\n";
        return Vaultify::Constants::EXIT_USAGE_ERROR;
    }

    // --- Initialize OpenSSL ---
    // Should be done before any OpenSSL functions are called by the application.
    initialize_openssl();

    // --- Application Execution ---
    int final_exit_code = Vaultify::Constants::EXIT_INTERNAL_ERROR; // Default to error
    try {
        Vaultify::UI::Application app; // Create the application object
        final_exit_code = app.run();   // Run the application, handles its own errors internally
        // and returns an appropriate exit code.
    } catch (const std::exception& e) {
        // Catch any catastrophic exceptions during app construction or unforeseen issues.
        std::cerr << "\nCritical Error: " << e.what() << std::endl;
        final_exit_code = Vaultify::Constants::EXIT_INTERNAL_ERROR;
    } catch (...) {
        std::cerr << "\nUnknown Critical Error occurred." << std::endl;
        final_exit_code = Vaultify::Constants::EXIT_INTERNAL_ERROR;
    }

    // --- Cleanup OpenSSL ---
    // Should be done after all OpenSSL functions have finished.
    cleanup_openssl();

    // --- Return Final Exit Code ---
    return final_exit_code;
}