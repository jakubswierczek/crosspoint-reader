add_executable(ObfuscationCodecTest ObfuscationCodecTest.cpp)

target_include_directories(ObfuscationCodecTest PRIVATE
  ${REPO_ROOT}/lib
)

target_link_libraries(ObfuscationCodecTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(ObfuscationCodecTest)
