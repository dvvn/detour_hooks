cmake_minimum_required(VERSION 3.0)

project(hde C)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(ARCH 64)
else()
  set(ARCH 32)
endif()

set(HDE_DIR ${CMAKE_CURRENT_LIST_DIR}/hde${ARCH})
set(HDE_SRC ${HDE_DIR}/source/hde${ARCH}.c)
set(HDE_INCLUDE_DIR ${HDE_DIR}/include)

add_library(hde ${HDE_SRC})
target_include_directories(hde PUBLIC ${HDE_INCLUDE_DIR})
