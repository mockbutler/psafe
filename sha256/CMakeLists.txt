include (CTest)

add_library(sha256 sha256.c)

add_executable(test test.c)
target_link_libraries(test sha256)
add_test(test test)
