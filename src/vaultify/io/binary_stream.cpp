#include "binary_stream.hpp"
#include "vaultify/types.hpp" // For Vaultify::IoError

#include <stdexcept> // For length_error in read_string

namespace Vaultify::IO {

    // --- Write Operations ---

    void write_bytes(std::ofstream& out, const byte* data, size_t size) {
        if (size == 0) return; // Nothing to write
        if (!data) throw Vaultify::InternalError("write_bytes called with null data pointer.");
        out.write(reinterpret_cast<const char*>(data), size);
        if (!out) {
            throw Vaultify::IoError("Failed to write " + std::to_string(size) + " bytes to output file stream.");
        }
    }

    void write_byte_vec(std::ofstream& out, const byte_vec& data) {
        write_bytes(out, data.data(), data.size());
    }

    void write_uint8(std::ofstream& out, uint8_t value) {
        out.put(static_cast<char>(value));
        if (!out) {
            throw Vaultify::IoError("Failed to write uint8_t to output file stream.");
        }
    }

    void write_uint16_network(std::ofstream& out, uint16_t value) {
        byte buffer[2];
        buffer[0] = static_cast<byte>((value >> 8) & 0xFF); // Most significant byte first
        buffer[1] = static_cast<byte>(value & 0xFF);        // Least significant byte last
        write_bytes(out, buffer, 2);
    }

    void write_uint64_network(std::ofstream& out, uint64_t value) {
        byte buffer[8];
        for (int i = 0; i < 8; ++i) {
            // Shift MSB down to current position
            buffer[i] = static_cast<byte>((value >> (56 - 8 * i)) & 0xFF);
        }
        write_bytes(out, buffer, 8);
    }

    void write_string(std::ofstream& out, const std::string& str) {
        write_bytes(out, reinterpret_cast<const byte*>(str.data()), str.length());
    }

    // --- Read Operations ---

    byte_vec read_exact_bytes(std::ifstream& in, size_t size) {
        if (size == 0) return {}; // Handle edge case
        byte_vec buffer(size);
        in.read(reinterpret_cast<char*>(buffer.data()), size);
        if (static_cast<size_t>(in.gcount()) != size) {
            std::string error_msg = "Failed to read expected " + std::to_string(size) + " bytes. ";
            if (in.eof()) {
                error_msg += "Reached end-of-file prematurely (read " + std::to_string(in.gcount()) + " bytes). File may be truncated or corrupted.";
            } else {
                error_msg += "File stream error (gcount=" + std::to_string(in.gcount()) + ").";
            }
            throw Vaultify::IoError(error_msg);
        }
        return buffer;
    }

    uint8_t read_uint8(std::ifstream& in) {
        int byte_int = in.get(); // Read as int to check for EOF
        if (byte_int == EOF) {
            std::string error_msg = "Failed to read uint8_t. ";
            if (in.eof()) {
                error_msg += "Reached end-of-file prematurely.";
            } else {
                error_msg += "File stream error.";
            }
            throw Vaultify::IoError(error_msg);
        }
        return static_cast<uint8_t>(byte_int);
    }

    uint16_t read_uint16_network(std::ifstream& in) {
        byte_vec buffer = read_exact_bytes(in, 2);
        // Network order: buffer[0] is MSB, buffer[1] is LSB
        return (static_cast<uint16_t>(buffer[0]) << 8) | static_cast<uint16_t>(buffer[1]);
    }

    uint64_t read_uint64_network(std::ifstream& in) {
        byte_vec buffer = read_exact_bytes(in, 8);
        uint64_t value = 0;
        for (int i = 0; i < 8; ++i) {
            // Shift byte up to its correct position and OR it in
            value |= static_cast<uint64_t>(buffer[i]) << (56 - 8 * i);
        }
        return value;
    }

    std::string read_string(std::ifstream& in, size_t length) {
        if (length == 0) return "";
        // Prevent excessive allocation based on potentially corrupt length
        const size_t MAX_REASONABLE_STRING = 1 * 1024 * 1024; // Example: 1MB limit
        if (length > MAX_REASONABLE_STRING) {
            throw Vaultify::IoError("Attempted to read excessively large string (length=" + std::to_string(length) + "). File header likely corrupt.");
        }
        try {
            std::string str(length, '\0'); // Pre-allocate string
            in.read(&str[0], length);      // Read directly into string's buffer (safe C++11 onwards)
            if (static_cast<size_t>(in.gcount()) != length) {
                std::string error_msg = "Failed to read expected string length " + std::to_string(length) + ". ";
                if (in.eof()) {
                    error_msg += "Reached end-of-file prematurely (read " + std::to_string(in.gcount()) + " bytes). File may be truncated or corrupted.";
                } else {
                    error_msg += "File stream error (gcount=" + std::to_string(in.gcount()) + ").";
                }
                throw Vaultify::IoError(error_msg);
            }
            return str;
        } catch(const std::length_error& e) {
            throw Vaultify::InternalError("Memory allocation failed reading string: " + std::string(e.what()));
        } catch(const std::bad_alloc& e) {
            throw Vaultify::InternalError("Memory allocation failed reading string: " + std::string(e.what()));
        }
    }

    // --- Seek/Tell Operations ---

    std::streampos get_stream_size(std::ifstream& in) {
        std::streampos original_pos = in.tellg();
        if (original_pos == -1) {
            throw Vaultify::IoError("Could not get current stream position before getting size.");
        }
        in.seekg(0, std::ios::end);
        if (!in) {
            throw Vaultify::IoError("Could not seek to end of stream to get size.");
        }
        std::streampos size = in.tellg();
        if (size == -1) {
            throw Vaultify::IoError("Could not get stream size after seeking to end.");
        }
        in.seekg(original_pos); // Restore original position
        if (!in) {
            throw Vaultify::IoError("Could not seek back to original stream position after getting size.");
        }
        return size;
    }

    void seek_abs(std::ifstream& in, std::streampos pos) {
        in.seekg(pos);
        if (!in) {
            throw Vaultify::IoError("Failed to seek to absolute position " + std::to_string(pos) + " in input stream.");
        }
    }

    std::streampos current_pos(std::ifstream& in) {
        std::streampos pos = in.tellg();
        if (pos == -1) {
            throw Vaultify::IoError("Could not get current position in input stream.");
        }
        return pos;
    }


} // namespace Vaultify::IO