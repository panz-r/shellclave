cmake_minimum_required(VERSION 3.20)
project(ShellclaveComponentRedirect LANGUAGES C CXX)

message(STATUS "shellgate is built by the repository-root Shellclave project")
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/.." shellclave-root)
