#ifndef VAULTIFY_IO_BINARY_STREAM_HPP
#define VAULTIFY_IO_BINARY_STREAM_HPP

#include "vaultify/types.hpp" // Vaultify::byte_vec etc.
#include <fstream>            // std::ifstream, std::ofstream
#include <vector>             // std::vector
#include <string>             // std::string

namespace Vaultify::IO {

    /** @brief Writes raw bytes to an output file stream. Throws IoError on failure. */
    void write_bytes(std::ofstream& out, const byte* data, size_t size);

    /** @brief Writes a byte vector to an output file stream. Throws IoError on failure. */
    void write_byte_vec(std::ofstream& out, const byte_vec& data);

    /** @brief Writes a single byte (uint8_t) to an output file stream. Throws IoError on failure. */
    void write_uint8(std::ofstream& out, uint8_t value);

    /** @brief Writes a uint16_t in network byte order (Big Endian) to an output file stream. Throws IoError on failure. */
    void write_uint16_network(std::ofstream& out, uint16_t value);

    /** @brief Writes a uint64_t in network byte order (Big Endian) to an output file stream. Throws IoError on failure. */
    void write_uint64_network(std::ofstream& out, uint64_t value);

    /** @brief Writes the raw bytes of a string to an output file stream. Throws IoError on failure. */
    void write_string(std::ofstream& out, const std::string& str);

    /** @brief Reads exactly 'size' bytes from an input file stream. Throws IoError on failure or if not enough bytes are available. */
    byte_vec read_exact_bytes(std::ifstream& in, size_t size);

    /** @brief Reads a single byte (uint8_t) from an input file stream. Throws IoError on failure. */
    uint8_t read_uint8(std::ifstream& in);

    /** @brief Reads a uint16_t in network byte order (Big Endian) from an input file stream. Throws IoError on failure. */
    uint16_t read_uint16_network(std::ifstream& in);

    /** @brief Reads a uint64_t in network byte order (Big Endian) from an input file stream. Throws IoError on failure. */
    uint64_t read_uint64_network(std::ifstream& in);

    /** @brief Reads 'length' raw bytes from an input file stream into a string. Throws IoError on failure. */
    std::string read_string(std::ifstream& in, size_t length);

    /** @brief Determines the total size of the file associated with the input stream. Throws IoError on failure. */
    std::streampos get_stream_size(std::ifstream& in);

    /** @brief Seeks to an absolute position in the input stream. Throws IoError on failure. */
    void seek_abs(std::ifstream& in, std::streampos pos);

    /** @brief Gets the current position in the input stream. Throws IoError on failure. */
    std::streampos current_pos(std::ifstream& in);

} // namespace Vaultify::IO

#endif // VAULTIFY_IO_BINARY_STREAM_HPP