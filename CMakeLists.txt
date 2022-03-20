project(psafe)
cmake_minimum_required(VERSION 3.10)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(Cryptopp REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wextra -std=c++11")

include_directories(${CRYPTOPP_INCLUDE_DIR})
add_executable(psafe psafe.cpp psafe.h mapfile.cpp mapfile.h)
target_link_libraries(psafe ${CRYPTOPP_LIBRARIES})
