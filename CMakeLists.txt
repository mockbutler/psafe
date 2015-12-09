project(psafe)
cmake_minimum_required(VERSION 2.6.0)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
		      ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -std=c99")
find_package(Gcrypt REQUIRED)
include_directories(${GCRYPT_INCLUDE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/sha256)
add_subdirectory (sha256)

add_executable(psafe psafe.c mapfile.c)
target_link_libraries(psafe ${GCRYPT_LIBRARIES} sha256)
