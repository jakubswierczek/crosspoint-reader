add_executable(HyphenationLanguageTagTest
  HyphenationLanguageTagTest.cpp
  ${REPO_ROOT}/lib/Epub/Epub/hyphenation/Hyphenator.cpp
  ${REPO_ROOT}/lib/Epub/Epub/hyphenation/LanguageRegistry.cpp
  ${REPO_ROOT}/lib/Epub/Epub/hyphenation/LiangHyphenation.cpp
  ${REPO_ROOT}/lib/Epub/Epub/hyphenation/HyphenationCommon.cpp
  ${REPO_ROOT}/lib/Utf8/Utf8.cpp
)

target_include_directories(HyphenationLanguageTagTest PRIVATE
  ${REPO_ROOT}/lib/Epub
  ${REPO_ROOT}/lib/Utf8
)

target_link_libraries(HyphenationLanguageTagTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(HyphenationLanguageTagTest)
