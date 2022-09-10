project(psafe)
cmake_minimum_required(VERSION 3.10)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

set(CXX_STANDARD_REQUIRED ON)
set(TARGET_NAME psafe)

set(SOURCES psafe.cpp psafe.h crypto.h fieldloader.h field.h ioutil.cpp ioutil.h record.h)
list(TRANSFORM SOURCES PREPEND "${CMAKE_SOURCE_DIR}/")

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

if (UNIX)
    add_compile_definitions(_GLIBCXX_USE_CXX11_ABI=0)
endif (UNIX)
add_executable(${TARGET_NAME} ${SOURCES})
set_property(TARGET ${TARGET_NAME} PROPERTY CXX_STANDARD 17)
target_link_libraries(${TARGET_NAME} ${CONAN_LIBS})
