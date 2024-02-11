
add_executable(util util.c)
target_link_libraries(psafe ${LIBGCRYPT_LDFLAGS})
target_compile_options(psafe PUBLIC ${LIBGCRYPT_CFLAGS_OTHER})

add_test(NAME util COMMAND util)
set_property(TARGET util PROPERTY C_STANDARD 17)
