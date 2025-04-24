#ifndef VAULTIFY_UI_APPLICATION_HPP
#define VAULTIFY_UI_APPLICATION_HPP

#include "vaultify/types.hpp" // Base types, Constants, Exceptions
#include <filesystem>         // For path handling
#include <string>

// No forward declarations needed anymore

namespace Vaultify::UI {

    /**
     * @brief Manages the command-line application lifecycle, user interaction,
     * file handling, and orchestration of the encryption/decryption process (Password-Only Mode).
     */
    class Application {
    public:
        Application() = default;
        Application(const Application&) = delete;
        Application& operator=(const Application&) = delete;
        Application(Application&&) = delete;
        Application& operator=(Application&&) = delete;

        int run();

    private:
        // --- User Interaction Helpers ---
        void print_usage() const;
        void print_banner() const;
        int prompt_operation() const; // Returns 1 for Encrypt, 2 for Decrypt
        // Removed: prompt_key_mode()
        std::filesystem::path prompt_for_path(const std::string& prompt_message, bool check_exists = false) const;
        std::string get_password_from_user(const std::string& prompt, bool confirm = false);

        // --- Core Workflow Steps ---
        void gather_inputs();
        void generate_output_path(); // New helper
        void validate_paths() const;
        // Derive key from password using provided salt.
        byte_vec derive_key_from_password(const std::string& password, const byte_vec& salt);
        void execute_processing();

        // --- Application State ---
        bool encrypt_mode_ = true;   // True if encrypting, false if decrypting
        // Removed: bool password_mode_;
        std::filesystem::path input_path_;
        std::filesystem::path output_path_; // Now automatically generated
        // Removed: keyfile_path_;
    };

} // namespace Vaultify::UI

#endif // VAULTIFY_UI_APPLICATION_HPP