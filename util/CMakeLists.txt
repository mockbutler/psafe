add_library(util util.c ioport.c)

add_executable(test_util test_util.c)
target_link_libraries(test_util util)

add_test(NAME test_util COMMAND test_util)
