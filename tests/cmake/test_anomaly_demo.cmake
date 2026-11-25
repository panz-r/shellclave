cmake_minimum_required(VERSION 3.20)

if(NOT DEFINED SHELLCLAVE_ANOMALY_DEMO OR NOT DEFINED SHELLCLAVE_ANOMALY_TEMP)
  message(FATAL_ERROR "Missing anomaly-demo test inputs")
endif()

file(REMOVE_RECURSE "${SHELLCLAVE_ANOMALY_TEMP}")
file(MAKE_DIRECTORY "${SHELLCLAVE_ANOMALY_TEMP}")
set(commands "${SHELLCLAVE_ANOMALY_TEMP}/commands.txt")
set(model "${SHELLCLAVE_ANOMALY_TEMP}/model.bin")
set(empty_model "${SHELLCLAVE_ANOMALY_TEMP}/empty.bin")
file(WRITE "${commands}"
  "cat a | grep b | sort\n"
  "cat c | grep d | sort\n")

# Training with -u -s reads standard input and saves what it learned. The
# first commands have three stages, and an empty model scores them INFINITY:
# that is nothing known, not an anomaly, so they are learned.
execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_DEMO}" -u -s "${model}"
  INPUT_FILE "${commands}"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "anomaly_demo training failed (${result}): ${error}")
endif()
if(output MATCHES "ANOMALOUS")
  message(FATAL_ERROR "an empty model flagged a command: ${output}")
endif()
string(REGEX MATCHALL "\\(learned\\)" learned "${output}")
list(LENGTH learned learned_count)
if(NOT learned_count EQUAL 2)
  message(FATAL_ERROR "anomaly_demo learned ${learned_count} of 2 commands: ${output}")
endif()

# An untrained model saved the same way is smaller than the trained one.
execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_DEMO}" -s "${empty_model}"
  INPUT_FILE /dev/null
  RESULT_VARIABLE result OUTPUT_QUIET ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "anomaly_demo empty save failed (${result}): ${error}")
endif()
file(SIZE "${model}" trained_size)
file(SIZE "${empty_model}" empty_size)
if(NOT trained_size GREATER empty_size)
  message(FATAL_ERROR "the saved model is untrained (${trained_size} <= ${empty_size} bytes)")
endif()

# The saved model scores a learned command with a finite score.
execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_DEMO}" -m "${model}"
  INPUT_FILE "${commands}"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0 OR output MATCHES "score=inf")
  message(FATAL_ERROR "the saved model does not score learned commands: ${output} ${error}")
endif()
