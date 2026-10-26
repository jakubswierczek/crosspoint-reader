add_executable(WebAccessTest WebAccessTest.cpp)

target_include_directories(WebAccessTest PRIVATE
  ${REPO_ROOT}/src
)

target_link_libraries(WebAccessTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(WebAccessTest)
