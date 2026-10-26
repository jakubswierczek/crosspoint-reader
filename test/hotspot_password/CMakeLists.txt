add_executable(HotspotPasswordTest HotspotPasswordTest.cpp)

target_include_directories(HotspotPasswordTest PRIVATE
  ${REPO_ROOT}/src
)

target_link_libraries(HotspotPasswordTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(HotspotPasswordTest)
