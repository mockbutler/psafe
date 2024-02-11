add_executable(psafe
    crypto.c crypto.h
    psafe.c psafe.h
    pws3.c pws3.h)
target_link_libraries(psafe ${LIBGCRYPT_LDFLAGS} util)
target_compile_options(psafe PUBLIC ${LIBGCRYPT_CFLAGS_OTHER})
