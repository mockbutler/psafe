project(psafe)
cmake_minimum_required(VERSION 3.10)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(Cryptopp REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wextra -std=c++17")
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

set(SOURCES psafe.cpp psafe.h crypto.h fieldloader.h field.h ioutil.cpp ioutil.h)
list(TRANSFORM SOURCES PREPEND "${CMAKE_SOURCE_DIR}/")

include_directories(${CRYPTOPP_INCLUDE_DIR})
add_executable(psafe ${SOURCES})
target_link_libraries(psafe ${CRYPTOPP_LIBRARIES})

add_custom_target(
    clang-tidy-check clang-tidy -p ${CMAKE_BINARY_DIR}/compile_commands.json -checks=cert*,cppcoreguidelines -header-filter='.*' ${SOURCES}
    DEPENDS ${SOURCES})

add_custom_target(check DEPENDS clang-tidy-check)