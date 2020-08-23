project(gg)
cmake_minimum_required(VERSION 3.17)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(Protobuf_USE_STATIC_LIBS TRUE)
include(FindProtobuf)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
option(BUILD_SHARED_LIBS "Use shared libraries" FALSE)
if (NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
endif()

option(CMAKE_BUILD_TYPE "Kind of Build" Release)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -static -s")

set(OPENSSL_USE_STATIC_LIBS TRUE)
set(OPENSSL_ROOT_DIR ${PROJECT_SOURCE_DIR}/third_party/install)
include(FindOpenSSL)

include(FindCRYPTOPP)

add_subdirectory(third_party/hiredis)

include_directories(src)
include_directories(${CMAKE_BINARY_DIR}/src)
add_subdirectory(src)
