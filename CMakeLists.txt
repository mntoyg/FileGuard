cmake_minimum_required(VERSION 3.16)
project(FileGuard VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(MSVC)
  add_compile_options(/W4 /WX)
else()
  add_compile_options(
    -Wall -Wextra -Wpedantic -Wshadow
    -Wno-unused-parameter
  )
endif() 

add_executable(fileguard
  src/main.cpp
  src/Encryptor.cpp
)

target_include_directories(fileguard PRIVATE include)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND
   CMAKE_CXX_COMPILER_VERSION VERSION_LESS "9.0")
  target_link_libraries(fileguard PRIVATE stdc++fs)
endif()

install(TARGETS fileguard DESTINATION bin)