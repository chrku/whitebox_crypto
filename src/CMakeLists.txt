cmake_minimum_required(VERSION 3.12)

if(COMMAND cmake_policy)
  cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

add_executable(whitebox)

include_directories(../include)

set(Boost_USE_STATIC_LIBS        ON)
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME    OFF)
find_package(Boost COMPONENTS program_options serialization REQUIRED)
find_library(NTL_LIB ntl)
if (NOT NTL_LIB)
    message(FATAL_ERROR "NTL not found.")
endif ()
find_library(CRYPTOPP_LIB cryptopp)
if (NOT CRYPTOPP_LIB)
    message(FATAL_ERROR "Crypto++ not found")
endif ()

target_sources(whitebox PRIVATE Main.cpp WhiteBoxTableGenerator.cpp
 WhiteBoxInterpreter.cpp AESUtils.cpp Test.cpp MixingBijection.cpp
 WhiteBoxCipher.cpp ExternalEncoding.cpp)
target_link_libraries(whitebox Boost::program_options Boost::serialization ntl m cryptopp)
