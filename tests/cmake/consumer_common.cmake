# Shared by the installed and embedded consumer tests.

# The path of a consumer executable built in build. A multi-config generator
# places it under the configuration's own directory.
function(consumer_executable result build name)
  if(SHELLCLAVE_GENERATOR MATCHES "Multi-Config|Visual Studio|Xcode")
    if(NOT SHELLCLAVE_BUILD_TYPE)
      message(FATAL_ERROR
        "A multi-config generator needs SHELLCLAVE_BUILD_TYPE to find ${name}")
    endif()
    set(${result} "${build}/${SHELLCLAVE_BUILD_TYPE}/${name}" PARENT_SCOPE)
  else()
    set(${result} "${build}/${name}" PARENT_SCOPE)
  endif()
endfunction()

# Run every consumer executable of build, naming the kind of consumer in a
# failure.
function(run_consumers build kind)
  foreach(name IN ITEMS shellclave_consumer shellclave_cpp_consumer
          shellclave_shelltype_consumer shellclave_example_consumer
          shellclave_source_consumer)
    consumer_executable(executable "${build}" "${name}")
    execute_process(COMMAND "${executable}" RESULT_VARIABLE result)
    if(result)
      message(FATAL_ERROR "${kind} ${name} execution failed: ${result}")
    endif()
  endforeach()
endfunction()
