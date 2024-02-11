cmake_minimum_required(VERSION 3.20)
project(psafe)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBGCRYPT REQUIRED libgcrypt)

enable_testing()

set(CMAKE_C_STANDARD 17)
add_compile_options(-Wall -Wextra -Werror)

include_directories(${LIBGCRYPT_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR})

add_subdirectory(util)

add_executable(psafe
    crypto.c crypto.h
    psafe.c psafe.h
    pws3.c pws3.h)
target_link_libraries(psafe ${LIBGCRYPT_LDFLAGS} util)
target_compile_options(psafe PUBLIC ${LIBGCRYPT_CFLAGS_OTHER})

