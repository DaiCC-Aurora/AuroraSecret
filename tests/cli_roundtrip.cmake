# End to end test of the aurorasecret executable.
#
# Run by CTest as: cmake -DAURORASECRET_EXE=<binary> -DWORK_DIR=<dir> -P this_file
# Using CMake instead of a shell script keeps it identical on Windows, Linux and
# macOS and avoids all command line quoting problems.
cmake_minimum_required(VERSION 3.16)

if(NOT AURORASECRET_EXE)
  message(FATAL_ERROR "AURORASECRET_EXE is not set")
endif()
if(NOT WORK_DIR)
  message(FATAL_ERROR "WORK_DIR is not set")
endif()

set(PASSWORD "correct horse battery staple")
set(FAST_ARGS --argon2-blocks 16 --argon2-passes 1 --no-progress)

function(expect_success what)
  execute_process(COMMAND ${ARGN} RESULT_VARIABLE result
                  OUTPUT_VARIABLE out ERROR_VARIABLE err)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "${what} failed with exit code ${result}\nstdout: ${out}\nstderr: ${err}")
  endif()
endfunction()

# ---------------------------------------------------------------- preparation
file(REMOVE_RECURSE "${WORK_DIR}")
file(MAKE_DIRECTORY "${WORK_DIR}/input/sub")
file(MAKE_DIRECTORY "${WORK_DIR}/input/empty dir")
file(WRITE "${WORK_DIR}/input/hello.txt" "hello world\n")
file(WRITE "${WORK_DIR}/input/empty.bin" "")
file(WRITE "${WORK_DIR}/input/sub/nested.bin" "nested payload\n")

# ------------------------------------------------------------------- encrypt
expect_success("encrypt"
  "${AURORASECRET_EXE}" encrypt "${WORK_DIR}/input"
  -o "${WORK_DIR}/backup.asf" -p "${PASSWORD}" ${FAST_ARGS})

if(NOT EXISTS "${WORK_DIR}/backup.asf")
  message(FATAL_ERROR "encrypt did not create the archive")
endif()

# An existing archive must not be replaced silently.
execute_process(COMMAND "${AURORASECRET_EXE}" encrypt "${WORK_DIR}/input"
                        -o "${WORK_DIR}/backup.asf" -p "${PASSWORD}" ${FAST_ARGS}
                RESULT_VARIABLE refuse_result OUTPUT_QUIET ERROR_QUIET)
if(refuse_result EQUAL 0)
  message(FATAL_ERROR "an existing archive was overwritten without --force")
endif()

# ---------------------------------------------------------------------- list
execute_process(COMMAND "${AURORASECRET_EXE}" list "${WORK_DIR}/backup.asf"
                        -p "${PASSWORD}"
                RESULT_VARIABLE list_result OUTPUT_VARIABLE list_out
                ERROR_VARIABLE list_err)
if(NOT list_result EQUAL 0)
  message(FATAL_ERROR "list failed with exit code ${list_result}: ${list_err}")
endif()
if(NOT list_out MATCHES "input/hello\\.txt")
  message(FATAL_ERROR "list output does not mention input/hello.txt:\n${list_out}")
endif()
if(NOT list_out MATCHES "input/empty dir/")
  message(FATAL_ERROR "list output does not mention 'input/empty dir/':\n${list_out}")
endif()

# The list command needs the right password.
execute_process(COMMAND "${AURORASECRET_EXE}" list "${WORK_DIR}/backup.asf"
                        -p "not the password"
                RESULT_VARIABLE bad_list_result OUTPUT_QUIET ERROR_QUIET)
if(bad_list_result EQUAL 0)
  message(FATAL_ERROR "list accepted a wrong password")
endif()

# ------------------------------------------------------------------- dry run
expect_success("dry run"
  "${AURORASECRET_EXE}" decrypt "${WORK_DIR}/backup.asf"
  -o "${WORK_DIR}/dry" -p "${PASSWORD}" --dry-run --no-progress)
if(EXISTS "${WORK_DIR}/dry")
  message(FATAL_ERROR "a dry run created files")
endif()

# ------------------------------------------------------------------- decrypt
expect_success("decrypt"
  "${AURORASECRET_EXE}" decrypt "${WORK_DIR}/backup.asf"
  -o "${WORK_DIR}/output" -p "${PASSWORD}" --no-progress)

file(READ "${WORK_DIR}/output/input/hello.txt" hello)
if(NOT hello STREQUAL "hello world\n")
  message(FATAL_ERROR "hello.txt was not restored correctly: '${hello}'")
endif()

if(NOT EXISTS "${WORK_DIR}/output/input/empty.bin")
  message(FATAL_ERROR "the empty file was not restored")
endif()
file(SIZE "${WORK_DIR}/output/input/empty.bin" empty_size)
if(NOT empty_size EQUAL 0)
  message(FATAL_ERROR "the restored empty file is not empty")
endif()

if(NOT IS_DIRECTORY "${WORK_DIR}/output/input/empty dir")
  message(FATAL_ERROR "the empty directory was not restored")
endif()

file(READ "${WORK_DIR}/output/input/sub/nested.bin" nested)
if(NOT nested STREQUAL "nested payload\n")
  message(FATAL_ERROR "nested.bin was not restored correctly: '${nested}'")
endif()

# ------------------------------------------------------- wrong password path
execute_process(COMMAND "${AURORASECRET_EXE}" decrypt "${WORK_DIR}/backup.asf"
                        -o "${WORK_DIR}/wrong" -p "not the password" --force
                        --no-progress
                RESULT_VARIABLE wrong_result OUTPUT_QUIET ERROR_QUIET)
if(wrong_result EQUAL 0)
  message(FATAL_ERROR "a wrong password was accepted")
endif()
if(NOT wrong_result EQUAL 2)
  message(FATAL_ERROR "expected exit code 2 for a wrong password, got ${wrong_result}")
endif()

# ------------------------------------------------------------- usage errors
execute_process(COMMAND "${AURORASECRET_EXE}" frobnicate
                RESULT_VARIABLE unknown_result OUTPUT_QUIET ERROR_QUIET)
if(NOT unknown_result EQUAL 1)
  message(FATAL_ERROR "an unknown command must exit with code 1, got ${unknown_result}")
endif()

execute_process(COMMAND "${AURORASECRET_EXE}" encrypt --argon2-blocks 1
                RESULT_VARIABLE tiny_result OUTPUT_QUIET ERROR_QUIET)
if(NOT tiny_result EQUAL 1)
  message(FATAL_ERROR "an out of range Argon2 setting must exit with code 1, got ${tiny_result}")
endif()

message(STATUS "aurorasecret command line round trip succeeded")