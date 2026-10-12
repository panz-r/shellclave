cmake_minimum_required(VERSION 3.20)
project(ShellclaveAnalyzerContract LANGUAGES C CXX)

set(SHELLCLAVE_ANALYZER_FIXTURE clean CACHE STRING "Analyzer contract fixture")
if(NOT SHELLCLAVE_ANALYZER_FIXTURE MATCHES "^(clean|c|cpp)$")
  message(FATAL_ERROR "Unknown analyzer contract fixture")
endif()

# These fixtures are only compiled/analyzed, never executed. They do not call
# library APIs or violate any library caller precondition.
add_library(analyzer_c_probe STATIC probe.c)
add_library(analyzer_cpp_probe STATIC probe.cpp)
target_compile_features(analyzer_c_probe PRIVATE c_std_11)
target_compile_features(analyzer_cpp_probe PRIVATE cxx_std_11)
if(SHELLCLAVE_ANALYZER_FIXTURE STREQUAL "c")
  target_compile_definitions(analyzer_c_probe PRIVATE ANALYZER_DEFECT=1)
else()
  target_compile_definitions(analyzer_c_probe PRIVATE ANALYZER_DEFECT=0)
endif()
if(SHELLCLAVE_ANALYZER_FIXTURE STREQUAL "cpp")
  target_compile_definitions(analyzer_cpp_probe PRIVATE ANALYZER_DEFECT=1)
else()
  target_compile_definitions(analyzer_cpp_probe PRIVATE ANALYZER_DEFECT=0)
endif()
