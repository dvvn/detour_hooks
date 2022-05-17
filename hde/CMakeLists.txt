cmake_minimum_required(VERSION 3.0)

project(hde C)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(HDE_DIR "${CMAKE_CURRENT_LIST_DIR}/hde64")
else()
  set(HDE_DIR "${CMAKE_CURRENT_LIST_DIR}/hde32")
endif()

set(HDE_SRC "${HDE_DIR}/source/hde.c")
set(HDE_INCLUDE_DIR "${HDE_DIR}/include")

add_library(hde ${HDE_SRC})
target_include_directories(hde PUBLIC ${HDE_INCLUDE_DIR})

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  target_compile_definitions(hde PUBLIC HDE_DATA=hde64s HDE_DISASM=hde64_disasm)
else()
  target_compile_definitions(hde PUBLIC HDE_DATA=hde32s HDE_DISASM=hde32_disasm)
endif()
