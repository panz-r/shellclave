cmake_minimum_required(VERSION 3.20)

# CMake supplies the aggregate's actual dependencies, not a second suite list.
# CTest discovery works before executables exist; only names/labels are needed.
execute_process(
  COMMAND "${SHELLCLAVE_CTEST_COMMAND}" --test-dir "${SHELLCLAVE_BINARY_DIR}"
    --show-only=json-v1
  RESULT_VARIABLE status
  OUTPUT_VARIABLE registration
  ERROR_VARIABLE errors)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "CTest discovery failed (${status}):\n${errors}")
endif()

string(JSON test_count LENGTH "${registration}" tests)
if(test_count EQUAL 0)
  message(FATAL_ERROR "The production suite has no registered tests")
endif()
math(EXPR last_test "${test_count} - 1")
set(production_tests)
set(registered_tests)
set(reference_bash_tests
  shellsplit_bash_read_input
  shellsplit_bash_allocation_correlation
  shellsplit_bash_selector_lifecycle
  shellsplit_bash_read_proofs
  shellsplit_bash_private_read_outcomes
  shellsplit_bash_outcome_transfers)
foreach(index RANGE 0 ${last_test})
  string(JSON name GET "${registration}" tests ${index} name)
  list(APPEND registered_tests "${name}")
  string(JSON property_count LENGTH "${registration}" tests ${index} properties)
  set(labels)
  unset(timeout)
  if(property_count GREATER 0)
    math(EXPR last_property "${property_count} - 1")
    foreach(property RANGE 0 ${last_property})
      string(JSON property_name GET "${registration}"
        tests ${index} properties ${property} name)
      if(property_name STREQUAL "LABELS")
        string(JSON label_count LENGTH "${registration}"
          tests ${index} properties ${property} value)
        if(label_count GREATER 0)
          math(EXPR last_label "${label_count} - 1")
          foreach(label RANGE 0 ${last_label})
            string(JSON value GET "${registration}"
              tests ${index} properties ${property} value ${label})
            list(APPEND labels "${value}")
          endforeach()
        endif()
      elseif(property_name STREQUAL "TIMEOUT")
        string(JSON timeout GET "${registration}"
          tests ${index} properties ${property} value)
      endif()
    endforeach()
  endif()
  if("production" IN_LIST labels)
    list(APPEND production_tests "${name}")
    foreach(component IN ITEMS shellsplit shelltype shellgate)
      if(name MATCHES "^${component}_" AND NOT "${component}" IN_LIST labels)
        message(FATAL_ERROR
          "Production test ${name} lost its ${component} component label")
      endif()
    endforeach()
  elseif(name MATCHES "production")
    message(FATAL_ERROR
      "Production-named test ${name} lacks production suite registration")
  endif()
  if(name STREQUAL "shellgate_policy_sharing_test" AND
      NOT "concurrency" IN_LIST labels)
    message(FATAL_ERROR "Policy sharing lost its concurrency membership")
  endif()
  if(name IN_LIST reference_bash_tests)
    if(NOT "shellsplit" IN_LIST labels)
      message(FATAL_ERROR "Reference Bash test ${name} lost its shellsplit label")
    endif()
    if(NOT DEFINED timeout OR NOT timeout EQUAL 10)
      message(FATAL_ERROR
        "Reference Bash test ${name} must have a 10-second CTest timeout")
    endif()
  endif()
endforeach()

# These fixtures must remain independently scheduled.  Combining their
# individually bounded Bash processes would recreate a cumulative outer
# timeout and obscure the failing semantic contract.
foreach(required IN LISTS reference_bash_tests)
  if(NOT required IN_LIST registered_tests)
    message(FATAL_ERROR "Missing independent reference Bash test: ${required}")
  endif()
endforeach()

list(SORT production_tests)
list(SORT SHELLCLAVE_PRODUCTION_TARGETS)
if(NOT "${production_tests}" STREQUAL "${SHELLCLAVE_PRODUCTION_TARGETS}")
  message(FATAL_ERROR
    "Production build/test membership differs:\n"
    "  build: ${SHELLCLAVE_PRODUCTION_TARGETS}\n"
    "  tests: ${production_tests}")
endif()

# Explicit regressions for the executables omitted by the old CI build list.
foreach(required IN ITEMS shellsplit_boundary_production_test
    shellsplit_read_input_production_test shellgate_policy_sharing_test)
  if(NOT required IN_LIST production_tests)
    message(FATAL_ERROR "Missing production suite member: ${required}")
  endif()
endforeach()
list(LENGTH production_tests count)
message(STATUS "Production build and test selection agree (${count} tests)")
