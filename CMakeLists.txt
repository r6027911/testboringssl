cmake_minimum_required(VERSION 3.0.0)
project(TestBoringSsl VERSION 0.1.0 LANGUAGES C CXX)
set (CMAKE_CXX_STANDARD 17)
set(CMAKE_GENERATOR "Ninja")
include_directories(${CMAKE_SOURCE_DIR}/boringssl/include/ 
			${CMAKE_SOURCE_DIR}/third_party/jsoncpp/include/
			${CMAKE_SOURCE_DIR}/third_party/brotli/c/include/
			${CMAKE_SOURCE_DIR}/third_party/zlib/
			${CMAKE_SOURCE_DIR}/third_party/zstd/lib/
			${CMAKE_BINARY_DIR}/third_party/zlib/
) 

include(CTest)
enable_testing()

add_subdirectory("third_party/zlib")
add_subdirectory("third_party/zstd/build/cmake")
add_subdirectory("third_party/brotli")
add_subdirectory("third_party/jsoncpp")

add_subdirectory("boringssl")

add_executable(TestBoringSsl TestBoringSSL.cpp transport_common.cpp)


target_include_directories (TestBoringSsl 
						PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/build/third_party/zstd/build/cmake/lib/
						PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/build/third_party/brotli/
						PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/build/third_party/zlib/
						PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/build/boringssl/build/ 
						)


target_link_libraries (TestBoringSsl 
				zlibstatic
				libzstd_static
				brotlienc 
				brotlidec 
				brotlicommon
				jsoncpp_static
				ssl 
				crypto 
				 )



set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
