project(psafe)
cmake_minimum_required(VERSION 3.10)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

set(TARGET_NAME psafe)

set(SOURCES psafe.cpp psafe.h crypto.h fieldloader.h field.h ioutil.cpp ioutil.h record.h)
list(TRANSFORM SOURCES PREPEND "${CMAKE_SOURCE_DIR}/")

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

add_executable(${TARGET_NAME} ${SOURCES})
target_compile_features(${TARGET_NAME} PRIVATE cxx_std_17)
target_link_libraries(${TARGET_NAME} ${CONAN_LIBS})
