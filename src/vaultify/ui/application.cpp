#include "application.hpp"
#include "vaultify/core/processor.hpp"      // The processing engine
#include "vaultify/io/file_header.hpp"      // For header operations
#include "vaultify/crypto/primitives.hpp"   // Key derivation, secure clear, etc.
#include "vaultify/types.hpp"               // Constants, Exceptions, types

#include <iostream>
#include <limits>
#include <fstream>
#include <memory>
#include <system_error>

namespace Vaultify::UI {

    // --- User Interaction Helper Implementations ---

    void Application::print_usage() const {
        std::cerr << "Vaultify - File Encryption/Decryption Tool (AES-256-GCM Password Mode)\n"; // Updated description
        std::cerr << "Version: " << static_cast<int>(Constants::VERSION) << "\n";
        std::cerr << "Usage: Run the executable without arguments and follow the prompts.\n";
        std::cerr << "Command-line arguments are not supported.\n";
    }

    void Application::print_banner() const {
        std::cout << R"(
========================================
           Vaultify v)" << static_cast<int>(Constants::VERSION) << R"(
  AES-256-GCM Password Encryption Tool
========================================
)" << std::endl; // Updated description
    }


    int Application::prompt_operation() const {
        int choice = 0;
        std::cout << "Select operation:\n";
        std::cout << "  1. Encrypt\n";
        std::cout << "  2. Decrypt\n";
        std::cout << "Choice [1-2]: ";
        while (!(std::cin >> choice) || (choice != 1 && choice != 2)) {
            std::cerr << "Invalid input. Please enter 1 or 2: ";
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return choice;
    }

    // Removed: prompt_key_mode()

    std::filesystem::path Application::prompt_for_path(const std::string& prompt_message, bool check_exists) const {
        std::string path_str;
        std::filesystem::path fs_path;
        bool first_attempt = true;
        while (true) {
            if (!first_attempt) {
                std::cout << "Please try again.\n";
            }
            first_attempt = false;
            std::cout << prompt_message << ": ";
            if (!std::getline(std::cin, path_str) || path_str.empty()) {
                std::cerr << "Error: Input cannot be empty." << std::endl;
                if (!std::cin) {
                    std::cin.clear();
                    throw UsageError("Input stream error while reading path.");
                }
                continue;
            }

            try {
                fs_path = path_str;

                if (check_exists && !std::filesystem::exists(fs_path)) {
                    std::cerr << "Error: File or directory does not exist: " << fs_path.string() << std::endl;
                    continue;
                }
                break;
            } catch (const std::exception& e) {
                std::cerr << "Error processing path '" << path_str << "': " << e.what() << std::endl;
            }
        }
        return fs_path;
    }

    std::string Application::get_password_from_user(const std::string& prompt, bool confirm) {
        std::string password;
        std::string confirmation;

        // TODO: Implement secure password input
        std::cout << prompt << ": ";
        if (!(std::cin >> password) || password.empty()) {
            if (!std::cin) std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            throw UsageError("Failed to read password or password was empty.");
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (confirm) {
            std::cout << "Confirm password: ";
            if (!(std::cin >> confirmation)) {
                Crypto::secure_zero_memory(password);
                if (!std::cin) std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                throw UsageError("Failed to read password confirmation.");
            }
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            if (password != confirmation) {
                Crypto::secure_zero_memory(password);
                Crypto::secure_zero_memory(confirmation);
                throw UsageError("Passwords do not match.");
            }
            Crypto::secure_zero_memory(confirmation);
        }
        return password;
    }

    // --- Core Workflow Step Implementations ---

    void Application::gather_inputs() {
        int operation_choice = prompt_operation();
        encrypt_mode_ = (operation_choice == 1);

        // Removed: Key mode prompt

        // Get only input path
        input_path_ = prompt_for_path("Enter path to input file", true /* check exists */);

        // Removed: Output path prompt
        // Removed: Keyfile path prompt
    }

    void Application::generate_output_path() {
        std::filesystem::path parent = input_path_.parent_path();
        std::string input_filename_str = input_path_.filename().string();

        if (encrypt_mode_) {
            // Encrypt: Append .CRYPT
            // Output: <original_filename>.CRYPT
            output_path_ = parent / (input_filename_str + Constants::ENCRYPT_POSTFIX);
        } else {
            // Decrypt: Remove .CRYPT if present
            if (input_filename_str.size() > Constants::ENCRYPT_POSTFIX.size() &&
                input_filename_str.substr(input_filename_str.size() - Constants::ENCRYPT_POSTFIX.size()) == Constants::ENCRYPT_POSTFIX)
            {
                // Input ends with .CRYPT, remove it
                std::string base_name = input_filename_str.substr(0, input_filename_str.size() - Constants::ENCRYPT_POSTFIX.size());
                // Prevent empty output filename if input was just ".CRYPT"
                if (base_name.empty()) {
                    throw UsageError("Input filename cannot be just '" + Constants::ENCRYPT_POSTFIX + "'.");
                }
                output_path_ = parent / base_name;
            } else {
                // Input didn't end with .CRYPT, use a fallback name convention
                std::string fallback_name = input_path_.stem().string() + input_path_.extension().string() + Constants::DECRYPT_FALLBACK_EXT;
                output_path_ = parent / fallback_name;
                std::cout << "Warning: Input filename '" << input_filename_str
                          << "' did not end with expected '" << Constants::ENCRYPT_POSTFIX
                          << "'. Output will be named: " << output_path_.filename().string() << std::endl;
            }
        }

        // Prevent overwriting the input file
        std::error_code ec;
        if (std::filesystem::equivalent(input_path_, output_path_, ec)) {
            // This case should ideally not happen with the current logic, but safety first.
            // If it does, make the output name unique.
            output_path_ = parent / (output_path_.filename().string() + ".output");
            std::cout << "Warning: Generated output path was identical to input path. Renaming output to: "
                      << output_path_.filename().string() << std::endl;
            // Re-check equivalence after renaming (highly unlikely to match now)
            if (std::filesystem::equivalent(input_path_, output_path_, ec)) {
                throw UsageError("Internal error: Could not generate unique output path distinct from input path: " + output_path_.string());
            }

        }

        std::cout << "Output file will be: " << output_path_.string() << std::endl;
    }


    void Application::validate_paths() const {
        // Check input file type
        if (!std::filesystem::is_regular_file(input_path_)) {
            throw IoError("Input path is not a regular file: " + input_path_.string());
        }

        // Check output directory (output_path_ should be generated by now)
        std::filesystem::path parent_dir = output_path_.parent_path();
        if (!parent_dir.empty() && !std::filesystem::is_directory(parent_dir)) {
            throw IoError("Output directory does not exist or is not a directory: " + parent_dir.string());
        }
        // Warn about overwrite (already handled by generate_output_path message)
        if (std::filesystem::exists(output_path_)) {
            std::cout << "Warning: Output file '" << output_path_.string() << "' exists and will be overwritten." << std::endl;
        }
    }

    // Simplified key derivation helper
    byte_vec Application::derive_key_from_password(const std::string& password, const byte_vec& salt) {
        std::cout << "Deriving key from password (this may take a moment)..." << std::endl;
        byte_vec key = Crypto::derive_key_pbkdf2(password, salt);
        return key; // Key is returned, caller clears password/salt
    }


    void Application::execute_processing() {
        Core::Processor processor;
        IO::FileHeader header;
        byte_vec key;
        std::string password; // Keep password in scope until key derived

        // Generate output path before opening files
        generate_output_path();

        // Open input file (RAII)
        std::ifstream in_file(input_path_, std::ios::binary);
        if (!in_file) throw IoError("Cannot open input file: " + input_path_.string());
        in_file.exceptions(std::ifstream::badbit);

        std::ofstream out_file;
        bool output_file_opened = false;

        try {
            if (encrypt_mode_) {
                // == ENCRYPTION FLOW ==
                uint64_t input_size = std::filesystem::file_size(input_path_);
                std::string input_filename = input_path_.filename().string();

                // 1. Init header (generates salt & nonce)
                header.initialize_for_encryption(input_filename, input_size);

                // 2. Get password
                password = get_password_from_user("Enter password", true /* confirm */);

                // 3. Derive key using header's salt
                key = derive_key_from_password(password, header.salt);
                Crypto::secure_zero_memory(password); // Clear password immediately

                // 4. Open output file
                out_file.open(output_path_, std::ios::binary | std::ios::trunc);
                if (!out_file) throw IoError("Cannot open output file: " + output_path_.string());
                output_file_opened = true;
                out_file.exceptions(std::ofstream::badbit | std::ofstream::failbit);

                // 5. Write header
                header.write(out_file);

                // 6. Process payload
                processor.encrypt_payload(in_file, out_file, key, header);

                std::cout << "Encryption successful: " << input_path_.string() << " -> " << output_path_.string() << std::endl;

            } else {
                // == DECRYPTION FLOW ==
                // 1. Read header
                if (!header.read(in_file)) {
                    throw IoError("Input file appears empty or header could not be read: " + input_path_.string());
                }
                size_t header_size_on_disk = header.get_disk_size();

                // 2. Get password
                password = get_password_from_user("Enter password", false /* no confirm */);

                // 3. Derive key using header's salt
                key = derive_key_from_password(password, header.salt);
                Crypto::secure_zero_memory(password); // Clear password immediately

                // 4. Open output file
                out_file.open(output_path_, std::ios::binary | std::ios::trunc);
                if (!out_file) throw IoError("Cannot open output file: " + output_path_.string());
                output_file_opened = true;
                out_file.exceptions(std::ofstream::badbit | std::ofstream::failbit);

                // 5. Process payload
                processor.decrypt_payload(in_file, out_file, key, header, header_size_on_disk);

                std::cout << "Decryption successful: " << input_path_.string() << " -> " << output_path_.string() << std::endl;
                if (!header.original_filename.empty()) {
                    std::cout << "  Original Filename (from header): " << header.original_filename << std::endl;
                }
                std::cout << "  Original Filesize (from header): " << header.original_filesize << " bytes" << std::endl;
            }

            // Close files explicitly on success
            if (out_file.is_open()) out_file.close();
            if (in_file.is_open()) in_file.close();

        } catch (...) {
            // Cleanup on Error
            if (out_file.is_open()) out_file.close();
            if (in_file.is_open()) in_file.close();
            Crypto::secure_zero_memory(key); // Clear key
            Crypto::secure_zero_memory(password); // Clear password just in case

            if (output_file_opened && std::filesystem::exists(output_path_)) {
                std::error_code ec;
                std::filesystem::remove(output_path_, ec);
                if (ec) {
                    std::cerr << "\nError during processing. Additionally, failed to remove incomplete output file '"
                              << output_path_.string() << "': " << ec.message() << std::endl;
                } else {
                    std::cerr << "\nError during processing. Incomplete output file '" << output_path_.string() << "' has been removed." << std::endl;
                }
            } else if (output_file_opened) {
                std::cerr << "\nError during processing. Output file was not created or already removed." << std::endl;
            } else {
                std::cerr << "\nError during processing (output file not created)." << std::endl;
            }
            throw; // Re-throw
        }

        // Final key cleanup on success path
        Crypto::secure_zero_memory(key);
    }


    int Application::run() {
        print_banner();
        int exit_code = Constants::EXIT_OK;

        try {
            gather_inputs();     // Get operation & input path
            generate_output_path(); // Determine output path automatically
            validate_paths();    // Check paths validity
            execute_processing(); // Perform the main work

        } catch (const VaultifyError& e) {
            std::cerr << "\nVaultify Error: " << e.what() << std::endl;
            exit_code = e.get_exit_code();
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "\nFilesystem Error: " << e.what() << "\n"
                      << "  Path1: " << e.path1().string() << "\n"
                      << "  Path2: " << e.path2().string() << std::endl;
            exit_code = Constants::EXIT_IO_ERROR;
        } catch (const std::ios_base::failure& e) {
            std::cerr << "\nI/O Stream Error: " << e.what() << std::endl;
            exit_code = Constants::EXIT_IO_ERROR;
        } catch (const std::exception& e) {
            std::cerr << "\nUnexpected Standard Exception: " << e.what() << std::endl;
            exit_code = Constants::EXIT_INTERNAL_ERROR;
        } catch (...) {
            std::cerr << "\nAn unknown error occurred." << std::endl;
            exit_code = Constants::EXIT_INTERNAL_ERROR;
        }

        return exit_code;
    }

} // namespace Vaultify::UI