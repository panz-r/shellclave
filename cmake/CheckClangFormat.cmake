if(NOT CLANG_FORMAT_EXECUTABLE)
  message(FATAL_ERROR "CLANG_FORMAT_EXECUTABLE is required")
endif()
if(NOT SHELLCLAVE_SOURCE_DIR)
  message(FATAL_ERROR "SHELLCLAVE_SOURCE_DIR is required")
endif()

file(GLOB_RECURSE sources LIST_DIRECTORIES false
  "${SHELLCLAVE_SOURCE_DIR}/shellsplit/*.c"
  "${SHELLCLAVE_SOURCE_DIR}/shellsplit/*.h"
  "${SHELLCLAVE_SOURCE_DIR}/shellsplit/*.cpp"
  "${SHELLCLAVE_SOURCE_DIR}/shelltype/*.c"
  "${SHELLCLAVE_SOURCE_DIR}/shelltype/*.h"
  "${SHELLCLAVE_SOURCE_DIR}/shelltype/*.cpp"
  "${SHELLCLAVE_SOURCE_DIR}/shellgate/*.c"
  "${SHELLCLAVE_SOURCE_DIR}/shellgate/*.h"
  "${SHELLCLAVE_SOURCE_DIR}/shellgate/*.cpp"
  "${SHELLCLAVE_SOURCE_DIR}/tests/*.c"
  "${SHELLCLAVE_SOURCE_DIR}/tests/*.h"
  "${SHELLCLAVE_SOURCE_DIR}/tests/*.cpp")
list(SORT sources)

set(unformatted "")
foreach(source IN LISTS sources)
  execute_process(
    COMMAND "${CLANG_FORMAT_EXECUTABLE}" --output-replacements-xml "${source}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE replacements
    ERROR_VARIABLE error)
  if(result)
    message(FATAL_ERROR "clang-format failed for ${source}: ${error}")
  endif()
  if(replacements MATCHES "<replacement ")
    file(RELATIVE_PATH relative "${SHELLCLAVE_SOURCE_DIR}" "${source}")
    string(APPEND unformatted "\n  ${relative}")
  endif()
endforeach()

if(unformatted)
  message(FATAL_ERROR
    "The following files require formatting:${unformatted}\n"
    "Run the CMake format target before committing.")
endif()
