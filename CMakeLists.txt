cmake_minimum_required(VERSION 3.0.0)
project(TestBoringSsl VERSION 0.1.0 LANGUAGES C CXX)
set (CMAKE_CXX_STANDARD 17)
set(CMAKE_GENERATOR "Ninja")
include_directories(${CMAKE_SOURCE_DIR}/boringssl/include ${CMAKE_SOURCE_DIR}/jsoncpp/include) 

include(CTest)
enable_testing()

add_subdirectory("boringssl")
add_subdirectory("jsoncpp")

add_executable(TestBoringSsl TestBoringSSL.cpp transport_common.cpp)

target_link_libraries (TestBoringSsl ssl crypto jsoncpp_static )
target_include_directories (TestBoringSsl PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/build/boringssl/build/ )

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
