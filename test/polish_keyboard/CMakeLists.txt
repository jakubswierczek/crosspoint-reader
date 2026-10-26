add_executable(PolishKeyboardTest PolishKeyboardTest.cpp)

target_include_directories(PolishKeyboardTest PRIVATE
  ${REPO_ROOT}/src/activities/util
)

target_link_libraries(PolishKeyboardTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(PolishKeyboardTest)
