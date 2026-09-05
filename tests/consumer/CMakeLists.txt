cmake_minimum_required(VERSION 3.20)
project(ShellclaveConsumer LANGUAGES C CXX)

if(SHELLCLAVE_EMBEDDED_SOURCE)
  set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
  set(SHELLCLAVE_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
  add_subdirectory("${SHELLCLAVE_EMBEDDED_SOURCE}" shellclave)
else()
  set(SHELLCLAVE_REQUIRED_VERSION "0.8.0" CACHE STRING
      "Required Shellclave package version")
  find_package(Shellclave ${SHELLCLAVE_REQUIRED_VERSION} CONFIG REQUIRED)
endif()

add_executable(shellclave_consumer main.c)
target_link_libraries(shellclave_consumer PRIVATE Shellclave::shellgate)

add_executable(shellclave_cpp_consumer main.cpp)
target_compile_features(shellclave_cpp_consumer PRIVATE cxx_std_11)
target_link_libraries(shellclave_cpp_consumer PRIVATE Shellclave::shellgate)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(shellclave_consumer PRIVATE -Wall -Wextra -Wpedantic)
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(shellclave_cpp_consumer PRIVATE -Wall -Wextra -Wpedantic)
endif()
