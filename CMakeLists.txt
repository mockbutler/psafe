cmake_minimum_required(VERSION 3.20)
project(psafe)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBGCRYPT REQUIRED libgcrypt)

enable_testing()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wextra -std=c11")

include_directories(${LIBGCRYPT_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR})

add_executable(psafe
    crypto.c crypto.h
    ioport.c ioport.h
    psafe.c psafe.h
    pws3.c pws3.h
    util.c util.h
    )
target_link_libraries(psafe ${LIBGCRYPT_LDFLAGS})
target_compile_options(psafe PUBLIC ${LIBGCRYPT_CFLAGS_OTHER})

add_subdirectory(test)
