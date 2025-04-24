#include "file_header.hpp"
#include "binary_stream.hpp"          // Uses IO helpers for read/write
#include "vaultify/crypto/primitives.hpp" // Uses Crypto::generate_random_bytes
#include "vaultify/types.hpp"         // For Constants, Exceptions

#include <cstring>                    // For memcpy, memcmp
#include <limits>                     // For numeric_limits
#include <vector>

namespace Vaultify::IO {

    FileHeader::FileHeader() {
        std::memcpy(magic, Vaultify::Constants::MAGIC_BYTES, sizeof(magic));
        version = Vaultify::Constants::VERSION;
    }

    void FileHeader::initialize_for_encryption(const std::string& filename, uint64_t filesize) {
        using namespace Vaultify::Constants; // Use constants easily

        // Always generate salt (since only password mode exists)
        salt = Crypto::generate_random_bytes(SALT_LEN);

        // Always generate nonce
        nonce = Crypto::generate_random_bytes(NONCE_LEN);

        // Validate and set filename/filesize
        if (filename.length() > std::numeric_limits<uint16_t>::max()) {
            throw UsageError("Original filename is too long (max " + std::to_string(std::numeric_limits<uint16_t>::max()) + " bytes).");
        }
        filename_len = static_cast<uint16_t>(filename.length());
        original_filename = filename;
        original_filesize = filesize;
    }

    void FileHeader::write(std::ofstream& out) const {
        using namespace Vaultify::Constants;

        write_bytes(out, magic, sizeof(magic));
        write_uint8(out, version);
        // Removed: write_uint8(out, mode_flag);

        // Always write salt
        if (salt.size() != SALT_LEN) throw InternalError("Header::write: Invalid salt size ("+std::to_string(salt.size())+").");
        write_byte_vec(out, salt);

        // Always write nonce
        if (nonce.size() != NONCE_LEN) throw InternalError("Header::write: Invalid nonce size ("+std::to_string(nonce.size())+").");
        write_byte_vec(out, nonce);

        write_uint16_network(out, filename_len);
        if (filename_len > 0) {
            write_string(out, original_filename);
        }
        write_uint64_network(out, original_filesize);
    }

    bool FileHeader::read(std::ifstream& in) {
        using namespace Vaultify::Constants;

        if (in.peek() == EOF) {
            return false;
        }

        byte_vec read_magic = read_exact_bytes(in, sizeof(magic));
        if (std::memcmp(read_magic.data(), MAGIC_BYTES, sizeof(magic)) != 0) {
            throw DecryptionError("Invalid file format: Magic bytes do not match.");
        }
        std::memcpy(magic, read_magic.data(), sizeof(magic));

        version = read_uint8(in);
        if (version != VERSION) {
            throw DecryptionError("Unsupported file version: " + std::to_string(version) + ". Expected: " + std::to_string(VERSION));
        }

        // Removed: Reading mode_flag

        // Always read salt
        salt = read_exact_bytes(in, SALT_LEN);

        // Always read nonce
        nonce = read_exact_bytes(in, NONCE_LEN);

        filename_len = read_uint16_network(in);
        original_filename.clear();
        if (filename_len > 0) {
            original_filename = read_string(in, filename_len);
        }

        original_filesize = read_uint64_network(in);

        return true;
    }

    Vaultify::byte_vec FileHeader::generate_aad() const {
        using namespace Vaultify::Constants;
        byte_vec aad;
        // Calculate required size (salt is always included now)
        size_t aad_size = 1 + // version
                          SALT_LEN +
                          NONCE_LEN +
                          2 + // filename_len field
                          filename_len +
                          8; // filesize
        aad.reserve(aad_size);

        aad.push_back(version);
        // Removed: aad.push_back(mode_flag);

        // Always include salt
        if (salt.size() != SALT_LEN) throw InternalError("Header::generate_aad: Invalid salt size ("+std::to_string(salt.size())+").");
        aad.insert(aad.end(), salt.begin(), salt.end());

        // Always include nonce
        if (nonce.size() != NONCE_LEN) throw InternalError("Header::generate_aad: Invalid nonce size ("+std::to_string(nonce.size())+").");
        aad.insert(aad.end(), nonce.begin(), nonce.end());

        // Add filename length
        byte fn_len_bytes[2];
        fn_len_bytes[0] = static_cast<byte>((filename_len >> 8) & 0xFF);
        fn_len_bytes[1] = static_cast<byte>(filename_len & 0xFF);
        aad.insert(aad.end(), fn_len_bytes, fn_len_bytes + 2);

        // Add filename
        if (filename_len > 0) {
            aad.insert(aad.end(), original_filename.begin(), original_filename.end());
        }

        // Add file size
        byte fs_bytes[8];
        for (int i = 0; i < 8; ++i) {
            fs_bytes[i] = static_cast<byte>((original_filesize >> (56 - 8 * i)) & 0xFF);
        }
        aad.insert(aad.end(), fs_bytes, fs_bytes + 8);

        if (aad.size() != aad_size) {
            throw InternalError("Internal error: AAD generated size (" + std::to_string(aad.size()) +
                                ") mismatch. Expected: " + std::to_string(aad_size));
        }

        return aad;
    }

    // Removed: is_password_mode()

    size_t FileHeader::get_disk_size() const {
        using namespace Vaultify::Constants;
        // Salt is always present now
        return sizeof(magic) +
               1 + // version
               SALT_LEN + // Always include salt size
               NONCE_LEN +
               2 + // filename_len field size
               filename_len + // Actual filename bytes
               8; // original_filesize field size
    }

} // namespace Vaultify::IO