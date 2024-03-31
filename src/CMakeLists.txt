add_library(util util.c ioport.c)

add_executable(test_util test_util.c)
target_link_libraries(test_util util)

add_test(NAME test_util COMMAND test_util)

add_executable(psafe
               crypto.c crypto.h
               psafe.c psafe.h
               pws3.c pws3.h)
target_link_libraries(psafe ${LIBGCRYPT_LDFLAGS} util)
target_compile_options(psafe PUBLIC ${LIBGCRYPT_CFLAGS_OTHER})
