#include "processor.hpp"
#include "vaultify/types.hpp"               // Constants, Exceptions
#include "vaultify/crypto/aes_gcm.hpp"      // AES-GCM functions
#include "vaultify/crypto/primitives.hpp"   // secure_zero_memory
#include "vaultify/io/file_header.hpp"      // FileHeader type (used via reference)
#include "vaultify/io/binary_stream.hpp"    // Stream helpers (read/write/seek)

#include <vector>
#include <memory> // For unique_ptr on context
#include <algorithm> // For std::min

namespace Vaultify::Core {

    // --- Private Helper Method ---

    void Processor::stream_process(std::ifstream& in, std::ofstream& out,
                                   const byte_vec& key, const byte_vec& nonce,
                                   const byte_vec& aad, std::streamsize payload_size,
                                   bool encrypt, const byte_vec* expected_tag)
    {
        using namespace Vaultify::Constants;
        using namespace Vaultify::Crypto;
        using namespace Vaultify::IO;

        // 1. Initialize AES-GCM Context
        EvpCipherCtxPtr ctx = initialize_context(key, nonce, encrypt);

        // 2. Provide AAD
        provide_aad(ctx.get(), aad);
        // AAD is usually derived from header, caller should clear the temporary AAD vector

        // 3. Process Payload in Chunks
        byte_vec in_buffer(FILE_BUFFER_SIZE);
        std::streamsize bytes_processed = 0;

        while (true) {
            std::streamsize bytes_to_read = in_buffer.size();
            if (!encrypt) { // Decryption: limit reading to payload_size
                if (bytes_processed >= payload_size) break; // Finished payload
                bytes_to_read = std::min(static_cast<std::streamsize>(in_buffer.size()),
                                         payload_size - bytes_processed);
                if (bytes_to_read <= 0) break; // Should not happen if payload_size is correct, but safety break
            }

            in.read(reinterpret_cast<char*>(in_buffer.data()), bytes_to_read);
            std::streamsize bytes_read = in.gcount();

            if (bytes_read > 0) {
                byte_vec out_chunk = process_update(ctx.get(), in_buffer.data(), static_cast<size_t>(bytes_read), encrypt);
                if (!out_chunk.empty()) {
                    write_byte_vec(out, out_chunk);
                }
                bytes_processed += bytes_read;
            }

            // Check for end of input or error
            if (bytes_read < bytes_to_read) {
                if (in.eof()) {
                    break; // Normal end of input file
                } else { // Includes in.fail()
                    throw IoError("Input file stream error during payload processing.");
                }
            }
            if (bytes_read == 0 && bytes_to_read > 0) { // Safety check
                throw IoError("Input file stream read 0 bytes unexpectedly during payload processing.");
            }
        }

        // 4. Finalize and Handle Tag
        if (encrypt) {
            byte_vec tag = finalize_encryption(ctx.get());
            // Any final block data from finalize_encryption is ignored here, as process_update handles output.
            write_byte_vec(out, tag); // Write the generated tag
            secure_zero_memory(tag);
        } else {
            // Decryption finalization
            if (!expected_tag) throw InternalError("decrypt_payload: Expected tag pointer is null.");
            byte_vec final_plaintext = finalize_decryption(ctx.get(), *expected_tag);
            if (!final_plaintext.empty()) {
                write_byte_vec(out, final_plaintext); // Write any final plaintext block
            }
            // Caller should clear the expected_tag vector
        }

        // 5. Sanity Checks (after processing)
        if (!encrypt && bytes_processed != payload_size) {
            // This indicates a discrepancy between expected size and actual bytes read
            throw IoError("Payload processing error: Processed byte count (" + std::to_string(bytes_processed) +
                          ") does not match expected payload size (" + std::to_string(payload_size) + "). File might be corrupt or header invalid.");
        }
        if (encrypt && payload_size != -1 && bytes_processed != payload_size) {
            // If payload size was known for encryption (e.g. if passed in), check it
            throw InternalError("Payload processing error: Encrypted byte count mismatch.");
        }

        // Ensure output is flushed
        out.flush();
        if (!out) {
            throw IoError("Failed to flush output stream after processing.");
        }
    }


    // --- Public Method Implementations ---

    void Processor::encrypt_payload(std::ifstream& in_file,
                                    std::ofstream& out_file,
                                    const byte_vec& key,
                                    const IO::FileHeader& header)
    {
        // Ensure input stream is at the beginning of the payload (usually position 0)
        IO::seek_abs(in_file, 0);

        // Generate AAD from the provided header
        byte_vec aad = header.generate_aad();

        // Call the common streaming function
        stream_process(in_file, out_file, key, header.nonce, aad,
                       -1, /* Payload size unknown/irrelevant for encrypt */
                       true, /* Encrypt mode */
                       nullptr /* No expected tag */);

        // Clear sensitive data derived from header
        Vaultify::Crypto::secure_zero_memory(aad);
    }


    void Processor::decrypt_payload(std::ifstream& in_file,
                                    std::ofstream& out_file,
                                    const byte_vec& key,
                                    const IO::FileHeader& header,
                                    size_t header_disk_size)
    {
        // Calculate payload size and read tag BEFORE processing
        std::streampos current_header_end = static_cast<std::streampos>(header_disk_size);
        std::streampos total_file_size = IO::get_stream_size(in_file); // Gets size and restores position

        if (total_file_size < static_cast<std::streampos>(header_disk_size + Vaultify::Constants::TAG_LEN)) {
            throw DecryptionError("Input file is too small (" + std::to_string(total_file_size)
                                  + " bytes) to contain header (" + std::to_string(header_disk_size)
                                  + " bytes) and tag (" + std::to_string(Vaultify::Constants::TAG_LEN) + " bytes).");
        }

        std::streamsize payload_size = total_file_size - current_header_end - static_cast<std::streampos>(Vaultify::Constants::TAG_LEN);
        if (payload_size < 0) {
            throw DecryptionError("Calculated negative payload size. File header or size calculation is incorrect.");
        }

        // Read the expected tag from the end of the file
        std::streampos tag_position = total_file_size - static_cast<std::streampos>(Vaultify::Constants::TAG_LEN);
        IO::seek_abs(in_file, tag_position);
        byte_vec expected_tag = IO::read_exact_bytes(in_file, Vaultify::Constants::TAG_LEN);

        // --- Ready to process ---

        // Reset stream position to the start of the encrypted payload (after header)
        IO::seek_abs(in_file, current_header_end);

        // Generate AAD from the header that was read
        byte_vec aad = header.generate_aad();

        // Call the common streaming function
        stream_process(in_file, out_file, key, header.nonce, aad,
                       payload_size, /* Expected payload size */
                       false, /* Decrypt mode */
                       &expected_tag /* Pass expected tag */);

        // Clear sensitive data
        Vaultify::Crypto::secure_zero_memory(aad);
        Vaultify::Crypto::secure_zero_memory(expected_tag);
    }

} // namespace Vaultify::Core