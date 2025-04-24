#ifndef VAULTIFY_IO_FILE_HEADER_HPP
#define VAULTIFY_IO_FILE_HEADER_HPP

#include "vaultify/types.hpp" // For Vaultify::byte_vec, Constants, Exceptions
#include <fstream>            // For stream types used in read/write
#include <string>
#include <vector>

namespace Vaultify::IO {

    /**
     * @brief Represents and manages the Vaultify file format header (Password-Only Mode).
     * Handles reading, writing, and AAD generation for the header structure.
     */
    class FileHeader {
    public:
        /** @brief Default constructor. Initializes magic bytes and default version. */
        FileHeader();

        // --- Header Fields ---
        byte magic[sizeof(Vaultify::Constants::MAGIC_BYTES)];
        uint8_t version = Vaultify::Constants::VERSION;
        // Removed: uint8_t mode_flag;
        Vaultify::byte_vec salt; // Always populated (for PBKDF2)
        Vaultify::byte_vec nonce; // Always populated (GCM Nonce)
        uint16_t filename_len = 0; // Length of original_filename in bytes
        std::string original_filename; // Original name of the encrypted file
        uint64_t original_filesize = 0; // Original size of the encrypted file in bytes

        /**
         * @brief Populates header fields for an encryption operation.
         * Generates a random salt (for PBKDF2) and nonce (for GCM).
         * @param filename The original filename to store in the header.
         * @param filesize The original file size to store in the header.
         * @throws UsageError if the filename is too long.
         * @throws InternalError if random byte generation fails.
         */
        void initialize_for_encryption(const std::string& filename, uint64_t filesize); // Removed bool param

        /**
         * @brief Writes the current header contents to an output file stream.
         * Always writes the salt field.
         * @param out The output file stream.
         * @throws IoError on write failures.
         * @throws InternalError if header state is inconsistent (e.g., wrong salt/nonce size).
         */
        void write(std::ofstream& out) const;

        /**
         * @brief Reads and populates the header fields from an input file stream.
         * Validates magic bytes and version. Always reads the salt field.
         * @param in The input file stream.
         * @return true if a valid header was read successfully.
         * @return false if the stream was at EOF before reading could start (empty file).
         * @throws IoError on read failures or unexpected EOF.
         * @throws DecryptionError if magic bytes, version, or critical fields are invalid/corrupt.
         */
        bool read(std::ifstream& in);

        /**
         * @brief Generates the Associated Data (AAD) byte vector based on the current header fields.
         * The AAD includes version, salt, nonce, filename length, filename, and file size.
         * This must match exactly between encryption and decryption.
         * @return A byte vector containing the AAD.
         * @throws InternalError if header state is inconsistent (e.g., wrong salt/nonce size).
         */
        Vaultify::byte_vec generate_aad() const;

        // Removed: bool is_password_mode() const;

        /**
         * @brief Calculates the total size of the header in bytes as stored on disk.
         * Always accounts for the salt field.
         * @return The size of the header in bytes.
         */
        size_t get_disk_size() const;
    };

} // namespace Vaultify::IO

#endif // VAULTIFY_IO_FILE_HEADER_HPP