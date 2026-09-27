if(NOT DEFINED SHELLCLAVE_ANOMALY_CALIBRATE OR
   NOT DEFINED SHELLCLAVE_ANOMALY_CORPUS OR
   NOT DEFINED SHELLCLAVE_ANOMALY_TEMP)
  message(FATAL_ERROR "Missing anomaly-calibrate test inputs")
endif()

# Corpus records are physical lines. Build a valid record larger than the old
# fixed reader buffer here so the integration test verifies that it remains one
# command rather than being split into synthetic records.
file(MAKE_DIRECTORY "${SHELLCLAVE_ANOMALY_TEMP}")
set(long_corpus "${SHELLCLAVE_ANOMALY_TEMP}/long-normal.txt")
string(REPEAT "x" 5000 long_argument)
set(nested_corpus "echo nested")
foreach(depth RANGE 1 16)
  string(PREPEND nested_corpus "printf '%s' \"$(")
  string(APPEND nested_corpus ")\"")
endforeach()
file(READ "${SHELLCLAVE_ANOMALY_CORPUS}" base_corpus)
file(WRITE "${long_corpus}" "${base_corpus}"
  "printf '%s' ${long_argument}; printf '%s' tail\n"
  "${nested_corpus}\n"
  "while true; do :; done\n")

execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${long_corpus}"
          -N 1 -r 17 -t 0,0,1 -f text
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "anomaly_calibrate failed (${result}): ${error}")
endif()
if(NOT error MATCHES "Loaded 5 normal commands")
  message(FATAL_ERROR "anomaly_calibrate did not evaluate the corpus: ${error}")
endif()
if(NOT error MATCHES "Skipped 1 unsupported corpus records")
  message(FATAL_ERROR "anomaly_calibrate did not report rejected source: ${error}")
endif()
if(NOT error MATCHES "Generated 5 synthetic anomalies")
  message(FATAL_ERROR "anomaly_calibrate did not generate synthetic anomalies: ${error}")
endif()
if(NOT error MATCHES "swap=2 insert=2 substitute=1 shuffle=0; seed=17")
  message(FATAL_ERROR "anomaly_calibrate did not use only applicable, changing perturbations: ${error}")
endif()
if(NOT output MATCHES "Threshold calibration results")
  message(FATAL_ERROR "anomaly_calibrate produced no calibration output: ${output}")
endif()
if(NOT output MATCHES "Normal: 5  Anomalies: 5")
  message(FATAL_ERROR "anomaly_calibrate reported an incomplete calibration: ${output}")
endif()

# A singleton is valid input for insertion and substitution, while shuffle
# needs distinct stages. In particular, a random identity shuffle must not
# fail a record that is otherwise shuffleable.
set(singleton_corpus "${SHELLCLAVE_ANOMALY_TEMP}/singleton-normal.txt")
file(WRITE "${singleton_corpus}" "printf singleton\n")
execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${singleton_corpus}"
          -N 1 -r 9 -p insert -t 0,0,1 -f text
  RESULT_VARIABLE singleton_result
  OUTPUT_VARIABLE singleton_output
  ERROR_VARIABLE singleton_error)
if(NOT singleton_result EQUAL 0 OR
   NOT singleton_error MATCHES "Generated 1 synthetic anomalies" OR
   NOT singleton_error MATCHES "insert=1")
  message(FATAL_ERROR
    "anomaly_calibrate could not insert into a singleton record: ${singleton_error}${singleton_output}")
endif()
set(missing_parent "${SHELLCLAVE_ANOMALY_TEMP}/missing-model-parent")
file(REMOVE_RECURSE "${missing_parent}")
execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${long_corpus}"
          -N 1 -r 17 -t 0,0,1 -f text -s "${missing_parent}/model.bin"
  RESULT_VARIABLE save_result
  OUTPUT_VARIABLE save_output
  ERROR_VARIABLE save_error)
if(save_result EQUAL 0)
  message(FATAL_ERROR "anomaly_calibrate reported a failed model save as success")
endif()
if(NOT save_output MATCHES "Threshold calibration results")
  message(FATAL_ERROR "anomaly_calibrate did not publish its report before model failure: ${save_output}")
endif()
if(NOT save_error MATCHES "Cannot save model to")
  message(FATAL_ERROR "anomaly_calibrate did not report the failed model save: ${save_error}")
endif()
if(save_error MATCHES "Model saved to")
  message(FATAL_ERROR "anomaly_calibrate printed a false model-save success: ${save_error}")
endif()

# A calibration corpus is trusted: a late, structurally unusual record must
# still enter training rather than being silently skipped by anomaly detection.
set(trusted_corpus "${SHELLCLAVE_ANOMALY_TEMP}/trusted-normal.txt")
file(WRITE "${trusted_corpus}" "")
foreach(repetition RANGE 1 5)
  file(APPEND "${trusted_corpus}" "aaa; bbb; ccc\n")
endforeach()
file(APPEND "${trusted_corpus}" "xxx; yyy; zzz\n")
execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}"
          -N 1 -r 17 -p shuffle -t 0,0,1 -f text
  RESULT_VARIABLE shuffle_result
  OUTPUT_VARIABLE shuffle_output
  ERROR_VARIABLE shuffle_error)
if(NOT shuffle_result EQUAL 0 OR
   NOT shuffle_error MATCHES "Generated 6 synthetic anomalies" OR
   NOT shuffle_error MATCHES "shuffle=6")
  message(FATAL_ERROR
    "anomaly_calibrate rejected an applicable seeded shuffle: ${shuffle_error}${shuffle_output}")
endif()
execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}"
          -N 1 -r 4 -t 0,0,1 -f csv
  RESULT_VARIABLE trusted_result
  OUTPUT_VARIABLE trusted_output
  ERROR_VARIABLE trusted_error)
if(NOT trusted_result EQUAL 0 OR
   NOT trusted_error MATCHES "Model trained \\(vocab=6\\)")
  message(FATAL_ERROR
    "anomaly_calibrate self-filtered trusted training data: ${trusted_error}${trusted_output}")
endif()

# Exact empirical AUC is independent of the threshold rows selected for
# display. The same seeded synthetic corpus must report it unchanged.
execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}"
          -N 1 -r 4 -t 0,0,1 -f csv
  RESULT_VARIABLE auc_one_result
  OUTPUT_VARIABLE auc_one_output
  ERROR_VARIABLE auc_one_error)
execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}"
          -N 1 -r 4 -t 0,20,20 -f csv
  RESULT_VARIABLE auc_many_result
  OUTPUT_VARIABLE auc_many_output
  ERROR_VARIABLE auc_many_error)
string(REGEX MATCH "auc=([0-9.]+)" auc_one_match "${auc_one_output}")
set(auc_one "${CMAKE_MATCH_1}")
string(REGEX MATCH "auc=([0-9.]+)" auc_many_match "${auc_many_output}")
set(auc_many "${CMAKE_MATCH_1}")
if(NOT auc_one_result EQUAL 0 OR NOT auc_many_result EQUAL 0 OR
   auc_one STREQUAL "" OR NOT auc_one STREQUAL auc_many)
  message(FATAL_ERROR
    "anomaly_calibrate AUC depended on threshold rows: ${auc_one_error}${auc_many_error}")
endif()

function(calibration_csv_thresholds report result)
  string(REPLACE "\n" ";" lines "${report}")
  set(thresholds "")
  foreach(line IN LISTS lines)
    if(line MATCHES "^[-+0-9.eE]+,")
      string(REGEX REPLACE ",.*" "" threshold "${line}")
      list(APPEND thresholds "${threshold}")
    endif()
  endforeach()
  set(${result} "${thresholds}" PARENT_SCOPE)
endfunction()

# A decimal endpoint that is an exact grid point must survive binary
# floating-point rounding; a genuinely non-multiple endpoint must not be
# included. The rendered values must retain enough precision to distinguish
# every point in machine-readable and human-readable reports.
execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}"
          -N 1 -r 4 -t 0.1,0.3,0.1 -f csv
  RESULT_VARIABLE inclusive_result
  OUTPUT_VARIABLE inclusive_output
  ERROR_VARIABLE inclusive_error)
calibration_csv_thresholds("${inclusive_output}" inclusive_thresholds)
list(LENGTH inclusive_thresholds inclusive_count)
if(NOT inclusive_result EQUAL 0 OR NOT inclusive_count EQUAL 3)
  message(FATAL_ERROR
    "anomaly_calibrate omitted the inclusive decimal endpoint: ${inclusive_error}${inclusive_output}")
endif()
list(GET inclusive_thresholds 2 inclusive_last)
if(NOT inclusive_last MATCHES "^0\\.29")
  message(FATAL_ERROR "anomaly_calibrate reported the wrong endpoint: ${inclusive_last}")
endif()

execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}"
          -N 1 -r 4 -t 0,0.29,0.1 -f csv
  RESULT_VARIABLE exclusive_result
  OUTPUT_VARIABLE exclusive_output
  ERROR_VARIABLE exclusive_error)
calibration_csv_thresholds("${exclusive_output}" exclusive_thresholds)
list(LENGTH exclusive_thresholds exclusive_count)
if(NOT exclusive_result EQUAL 0 OR NOT exclusive_count EQUAL 3)
  message(FATAL_ERROR
    "anomaly_calibrate included a non-multiple endpoint: ${exclusive_error}${exclusive_output}")
endif()

# The endpoint can be only one representable double below a grid point, or
# just below the 1001st point. Neither case may be rounded onto the grid by
# an epsilon or by a floating-point point-count estimate.
execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}"
          -N 1 -r 4 -t 0,1.9999999999999998,1 -f csv
  RESULT_VARIABLE near_result
  OUTPUT_VARIABLE near_output
  ERROR_VARIABLE near_error)
calibration_csv_thresholds("${near_output}" near_thresholds)
list(LENGTH near_thresholds near_count)
if(NOT near_result EQUAL 0 OR NOT near_count EQUAL 2)
  message(FATAL_ERROR
    "anomaly_calibrate included a near-miss endpoint: ${near_error}${near_output}")
endif()

execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}"
          -N 1 -r 4 -t 0,999.9999999999999,1 -f csv
  RESULT_VARIABLE near_limit_result
  OUTPUT_VARIABLE near_limit_output
  ERROR_VARIABLE near_limit_error)
calibration_csv_thresholds("${near_limit_output}" near_limit_thresholds)
list(LENGTH near_limit_thresholds near_limit_count)
if(NOT near_limit_result EQUAL 0 OR NOT near_limit_count EQUAL 1000)
  message(FATAL_ERROR
    "anomaly_calibrate miscounted a near-limit grid: ${near_limit_error}")
endif()

foreach(range IN ITEMS "1e-1,3e-1,1e-1" "0x0p0,0x1p0,0x1p-1"
                       "-0.3,-0.1,0.1" "-0.1,0.1,0.1")
  execute_process(
    COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}"
            -N 1 -r 4 -t "${range}" -f csv
    RESULT_VARIABLE notation_result
    OUTPUT_VARIABLE notation_output
    ERROR_VARIABLE notation_error)
  calibration_csv_thresholds("${notation_output}" notation_thresholds)
  list(LENGTH notation_thresholds notation_count)
  if(NOT notation_result EQUAL 0 OR NOT notation_count EQUAL 3)
    message(FATAL_ERROR
      "anomaly_calibrate misread threshold notation ${range}: ${notation_error}${notation_output}")
  endif()
endforeach()

foreach(format IN ITEMS csv json text)
  execute_process(
    COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}"
            -N 1 -r 4 -t 0,0.002,0.001 -f "${format}"
    RESULT_VARIABLE precision_result
    OUTPUT_VARIABLE precision_output
    ERROR_VARIABLE precision_error)
  if(NOT precision_result EQUAL 0)
    message(FATAL_ERROR
      "anomaly_calibrate failed the ${format} precision case: ${precision_error}")
  endif()
  if(format STREQUAL "csv")
    calibration_csv_thresholds("${precision_output}" precise_thresholds)
    list(LENGTH precise_thresholds precise_count)
    if(NOT precise_count EQUAL 3)
      message(FATAL_ERROR "CSV lost threshold rows: ${precision_output}")
    endif()
    list(GET precise_thresholds 1 second_threshold)
    list(GET precise_thresholds 2 third_threshold)
  elseif(format STREQUAL "json")
    string(JSON precise_count LENGTH "${precision_output}" points)
    if(NOT precise_count EQUAL 3)
      message(FATAL_ERROR "JSON lost threshold rows: ${precision_output}")
    endif()
    string(JSON second_threshold GET "${precision_output}" points 1 threshold)
    string(JSON third_threshold GET "${precision_output}" points 2 threshold)
  else()
    if(NOT precision_output MATCHES "(^|\n)0\\.001[^0-9]" OR
       NOT precision_output MATCHES "(^|\n)0\\.002[^0-9]")
      message(FATAL_ERROR "Text rounded distinct thresholds together: ${precision_output}")
    endif()
    continue()
  endif()
  if(second_threshold STREQUAL third_threshold OR
     NOT second_threshold MATCHES "^0\\.001" OR
     NOT third_threshold MATCHES "^0\\.002")
    message(FATAL_ERROR
      "${format} rounded distinct thresholds together: ${precision_output}")
  endif()
endforeach()

foreach(option IN ITEMS -N -r)
  execute_process(
    COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}"
            "${option}" " 1"
    RESULT_VARIABLE spaced_result
    OUTPUT_VARIABLE spaced_output
    ERROR_VARIABLE spaced_error)
  if(spaced_result EQUAL 0)
    message(FATAL_ERROR
      "anomaly_calibrate accepted whitespace in ${option}: ${spaced_output}")
  endif()
endforeach()

execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}"
          -N 1 -r 4 -t 0,999,1 -f csv
  RESULT_VARIABLE thousand_result
  OUTPUT_VARIABLE thousand_output
  ERROR_VARIABLE thousand_error)
calibration_csv_thresholds("${thousand_output}" thousand_thresholds)
list(LENGTH thousand_thresholds thousand_count)
if(NOT thousand_result EQUAL 0 OR NOT thousand_count EQUAL 1000)
  message(FATAL_ERROR
    "anomaly_calibrate rejected the 1000-point grid: ${thousand_error}")
endif()

# Invalid option values fail before calibration and never masquerade as an
# empty or silently capped result.
foreach(invalid_args IN ITEMS "-t;0,1,0" "-t;5,0,1" "-t;0,1000,1"
                                 "-t;10000000000000000,10000000000000002,1"
                                 "-N;bad" "-N;+1" "-N;-18446744073709551615"
                                 "-N;18446744073709551616" "-r;-0" "-r;+1"
                                 "-r;18446744073709551616" "-f;unknown")
  string(REPLACE ";" " " invalid_display "${invalid_args}")
  separate_arguments(invalid_list UNIX_COMMAND "${invalid_display}")
  execute_process(
    COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}" ${invalid_list}
    RESULT_VARIABLE invalid_result
    OUTPUT_VARIABLE invalid_output
    ERROR_VARIABLE invalid_error)
  if(invalid_result EQUAL 0)
    message(FATAL_ERROR "anomaly_calibrate accepted invalid options: ${invalid_display}")
  endif()
endforeach()

# Bound exact hexadecimal conversion before it can expand a valid-looking
# threshold into thousands of decimal digits. The limit is inclusive.
string(REPEAT "0" 1018 threshold_padding)
set(limit_threshold "0,1.${threshold_padding},1")
string(LENGTH "${limit_threshold}" limit_threshold_length)
if(NOT limit_threshold_length EQUAL 1024)
  message(FATAL_ERROR "Threshold length fixture is not at the input limit")
endif()
execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}"
          -N 1 -r 4 -t "${limit_threshold}" -f csv
  RESULT_VARIABLE limit_result
  OUTPUT_VARIABLE limit_output
  ERROR_VARIABLE limit_error)
calibration_csv_thresholds("${limit_output}" limit_thresholds)
list(LENGTH limit_thresholds limit_count)
if(NOT limit_result EQUAL 0 OR NOT limit_count EQUAL 2)
  message(FATAL_ERROR "anomaly_calibrate rejected the threshold length limit: ${limit_error}")
endif()

string(REPEAT "f" 1100 threshold_hex_digits)
execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}"
          -N 1 -r 4 -t "0,0x${threshold_hex_digits}p-4400,1" -f csv
  TIMEOUT 5
  RESULT_VARIABLE overlimit_result
  OUTPUT_VARIABLE overlimit_output
  ERROR_VARIABLE overlimit_error)
if(overlimit_result EQUAL 0 OR
   NOT overlimit_error MATCHES "1024-byte input limit")
  message(FATAL_ERROR "anomaly_calibrate did not bound exact threshold input: ${overlimit_result} ${overlimit_error}")
endif()

execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}"
          -N 1 -r 0 -t 0,0,1 -f csv
  RESULT_VARIABLE zero_seed_result
  OUTPUT_VARIABLE zero_seed_output
  ERROR_VARIABLE zero_seed_error)
if(NOT zero_seed_result EQUAL 0 OR NOT zero_seed_error MATCHES "seed=0")
  message(FATAL_ERROR "anomaly_calibrate rejected seed zero: ${zero_seed_error}")
endif()

# A stage longer than the learner's contract must be reported as an unlearned
# trusted record, not as a successful calibration with an empty model.
set(overlong_corpus "${SHELLCLAVE_ANOMALY_TEMP}/overlong-stage.txt")
string(REPEAT "x" 1024 overlong_stage)
file(WRITE "${overlong_corpus}" "\nwhile true; do :; done\n${overlong_stage}\n")
execute_process(
  COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${overlong_corpus}"
          -N 1 -r 1 -t 0,0,1 -f csv
  RESULT_VARIABLE overlong_result
  OUTPUT_VARIABLE overlong_output
  ERROR_VARIABLE overlong_error)
if(overlong_result EQUAL 0 OR
   NOT overlong_error MATCHES "Corpus line 3 did not enter the anomaly model")
  message(FATAL_ERROR "anomaly_calibrate accepted an unlearned record: ${overlong_error}${overlong_output}")
endif()

if(EXISTS "/dev/full")
  set(model_after_report_failure "${SHELLCLAVE_ANOMALY_TEMP}/no-model-after-report-failure.bin")
  file(REMOVE "${model_after_report_failure}")
  execute_process(
    COMMAND "${SHELLCLAVE_ANOMALY_CALIBRATE}" -n "${trusted_corpus}"
            -N 1 -r 4 -t 0,0,1 -f csv -o /dev/full
            -s "${model_after_report_failure}"
    RESULT_VARIABLE full_result
    OUTPUT_VARIABLE full_output
    ERROR_VARIABLE full_error)
  if(full_result EQUAL 0 OR NOT full_error MATCHES "Cannot write calibration output")
    message(FATAL_ERROR "anomaly_calibrate ignored an output write failure: ${full_error}${full_output}")
  endif()
  if(EXISTS "${model_after_report_failure}")
    message(FATAL_ERROR "anomaly_calibrate saved the model after report publication failed")
  endif()
endif()
