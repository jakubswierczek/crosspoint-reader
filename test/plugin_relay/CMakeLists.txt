add_executable(PluginRelayPolicyTest PluginRelayPolicyTest.cpp)

target_include_directories(PluginRelayPolicyTest PRIVATE
  ${REPO_ROOT}/src
)

target_link_libraries(PluginRelayPolicyTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(PluginRelayPolicyTest)
