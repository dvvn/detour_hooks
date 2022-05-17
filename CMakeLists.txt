cmake_minimum_required(VERSION 3.14)

include(hde/CMakeLists.txt)

project(dhooks CXX)

set(DHOOKS_DIR ${PROJECT_SOURCE_DIR}/impl)

file(GLOB_RECURSE DHOOKS_SRC ${DHOOKS_DIR}/*.cpp ${DHOOKS_DIR}/*.ixx)

add_library(dhooks ${DHOOKS_SRC})
add_library(dhooks::dhooks ALIAS dhooks)

target_link_libraries(dhooks PRIVATE hde)
get_target_property(HDE_INCLUDES hde INCLUDE_DIRECTORIES)
target_include_directories(dhooks PRIVATE ${HDE_INCLUDES})
get_target_property(HDE_DEFINES hde COMPILE_DEFINITIONS)
target_compile_definitions(dhooks PRIVATE ${HDE_DEFINES})

include(FetchContent)

FetchContent_Declare(nstd GIT_REPOSITORY https://github.com/dvvn/nstd.git)
FetchContent_MakeAvailable(nstd)
target_link_libraries(dhooks PRIVATE nstd::nstd)
get_target_property(NSTD_INCLUDES nstd::nstd INCLUDE_DIRECTORIES)
target_include_directories(dhooks PRIVATE ${NSTD_INCLUDES})
