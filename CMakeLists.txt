cmake_minimum_required(VERSION 3.10)
project(XRP_Sentinel)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Vcpkg integration
set(CMAKE_TOOLCHAIN_FILE "$ENV{USERPROFILE}/vcpkg/scripts/buildsystems/vcpkg.cmake"
 CACHE STRING "Vcpkg toolchain file")

# Add executable for post_quantum_crypto
add_executable(post_quantum_crypto post_quantum_crypto.cpp)

# Find and link OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(post_quantum_crypto PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Add other C++ components as needed
add_executable(quantum_safe_key_vault quantum_safe_key_vault.cpp)
target_link_libraries(quantum_safe_key_vault PRIVATE OpenSSL::SSL OpenSSL::Crypto)
