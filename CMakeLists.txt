cmake_minimum_required(VERSION 3.12) # For target_link_options if needed, and general features
project(Vaultify VERSION 1.0 LANGUAGES CXX)

# Set C++ standard (C++17 required for std::filesystem)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF) # Prefer standard C++, avoid compiler extensions

# Find OpenSSL dependency
# Ensures OpenSSL libraries and include paths are found. REQUIRED makes CMake fail if not found.
find_package(OpenSSL REQUIRED)

# Add the executable target
add_executable(vaultify
        # Main entry point
        src/main.cpp
        # User Interface component
        src/vaultify/ui/application.cpp
        # Core processing component
        src/vaultify/core/processor.cpp
        # Input/Output components
        src/vaultify/io/file_header.cpp
        src/vaultify/io/binary_stream.cpp
        # Crypto components
        src/vaultify/crypto/aes_gcm.cpp
        src/vaultify/crypto/primitives.cpp
        # Note: types.hpp is header-only, no source file needed here
)

# Specify include directories
# CMAKE_CURRENT_SOURCE_DIR is the top-level directory containing this CMakeLists.txt
# Adding 'src' allows includes like #include "vaultify/types.hpp"
# OpenSSL_INCLUDE_DIR is provided by find_package(OpenSSL)
target_include_directories(vaultify PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${OpenSSL_INCLUDE_DIR}
)

# Link required libraries
# OpenSSL::SSL and OpenSSL::Crypto are imported targets provided by find_package(OpenSSL)
target_link_libraries(vaultify PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
)

# Handle C++17 filesystem library linking (if needed)
# Modern CMake/compilers usually handle this automatically when CMAKE_CXX_STANDARD=17 is set.
# Add these lines only if you encounter linker errors related to std::filesystem.
# Check your compiler documentation for the correct flag.
# Examples:
# target_link_libraries(vaultify PRIVATE $<$<CXX_COMPILER_ID:GNU>:-lstdc++fs>) # GCC
# target_link_libraries(vaultify PRIVATE $<$<CXX_COMPILER_ID:Clang>:-lc++fs>) # Clang with libc++

# Optional: Enable more compiler warnings for better code quality
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(vaultify PRIVATE
            -Wall             # Enable common warnings
            -Wextra           # Enable more warnings
            -Wpedantic        # Warn on non-standard extensions
            -Wshadow          # Warn about variable shadowing
            -Wnon-virtual-dtor # Warn if base class has non-virtual destructor
            -Wold-style-cast  # Warn on C-style casts
            -Wcast-align      # Warn about potential alignment issues from casts
            -Wunused          # Warn about unused variables/parameters
            -Woverloaded-virtual # Warn about missed overrides
            # -Werror           # Uncomment to treat all warnings as errors during development
    )
endif()
if(MSVC)
    target_compile_options(vaultify PRIVATE
            /W4               # Enable level 4 warnings (high level)
            /wd4251           # Disable specific MSVC warnings if necessary (example)
            # /WX             # Uncomment to treat warnings as errors
    )
endif()

# Optional: Define an install target to place the executable in a standard location
# install(TARGETS vaultify DESTINATION bin)

# Optional: Enable testing with CTest (Requires separate test files)
# enable_testing()
# add_test(NAME VaultifyTests COMMAND vaultify_tests) # Assuming a 'vaultify_tests' executable exists