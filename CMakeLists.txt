cmake_minimum_required(VERSION 3.20)
project(psafe)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBCRYPTOXX REQUIRED libcrypto++)

set(CXX_STANDARD_REQUIRED ON)
set(TARGET_NAME psafe)

set(SOURCES psafe.cpp psafe.h crypto.h fieldloader.h field.h ioutil.cpp ioutil.h record.h)
list(TRANSFORM SOURCES PREPEND "${CMAKE_SOURCE_DIR}/")

add_executable(${TARGET_NAME} ${SOURCES})
set_property(TARGET ${TARGET_NAME} PROPERTY CXX_STANDARD 17)
target_link_libraries(${TARGET_NAME} ${LIBCRYPTOXX_LIBRARIES})
target_include_directories(${TARGET_NAME} PUBLIC ${LIBCRYPTOXX_INCLUDE_DIRS})
