
add_executable(test_util test_util.c ${CMAKE_SOURCE_DIR}/util.c)
target_link_libraries(psafe ${LIBGCRYPT_LDFLAGS})
target_compile_options(psafe PUBLIC ${LIBGCRYPT_CFLAGS_OTHER})

add_test(NAME test_util COMMAND test_util)
