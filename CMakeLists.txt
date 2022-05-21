cmake_minimum_required(VERSION 3.14)

include(hde/CMakeLists.txt)

project(dhooks CXX)

set(DHOOKS_DIR ${PROJECT_SOURCE_DIR}/impl)

file(GLOB_RECURSE DHOOKS_SRC ${DHOOKS_DIR}/*.cpp ${DHOOKS_DIR}/*.ixx)

add_library(dhooks ${DHOOKS_SRC})
add_library(dhooks::dhooks ALIAS dhooks)

target_link_libraries(dhooks PRIVATE hde)
target_include_directories(dhooks PRIVATE hde)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  target_compile_definitions(dhooks PRIVATE DHOOKS_X64=1)
endif()

include(FetchContent)

FetchContent_Declare(nstd GIT_REPOSITORY https://github.com/dvvn/nstd.git)
FetchContent_MakeAvailable(nstd)
target_link_libraries(dhooks PRIVATE nstd::core PRIVATE nstd::mem)
target_include_directories(dhooks PRIVATE nstd::core)
