add_executable(aurorasecret_tests test_main.cpp)
target_link_libraries(aurorasecret_tests PRIVATE aurorasecret_core)

if(MSVC)
  target_compile_options(aurorasecret_tests PRIVATE /W4 /utf-8 /permissive-)
else()
  target_compile_options(aurorasecret_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME aurorasecret.unit COMMAND aurorasecret_tests)
set_tests_properties(aurorasecret.unit PROPERTIES TIMEOUT 900)

add_test(NAME aurorasecret.cli.help COMMAND aurorasecret --help)
add_test(NAME aurorasecret.cli.version COMMAND aurorasecret --version)
add_test(NAME aurorasecret.cli.noargs COMMAND aurorasecret)
set_tests_properties(aurorasecret.cli.noargs PROPERTIES WILL_FAIL TRUE)

# End to end test of the real executable (encrypt, list, decrypt, failures).
add_test(
  NAME aurorasecret.cli.roundtrip
  COMMAND ${CMAKE_COMMAND}
          "-DAURORASECRET_EXE=$<TARGET_FILE:aurorasecret>"
          "-DWORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/cli-roundtrip"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/cli_roundtrip.cmake")
set_tests_properties(aurorasecret.cli.roundtrip PROPERTIES TIMEOUT 900)
