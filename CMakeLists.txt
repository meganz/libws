cmake_minimum_required (VERSION 2.6) 

project(libws)
set(PROJECT_VERSION 0.2.0)

option(LIBWS_WITH_TESTS "Build test suite" OFF)
option(LIBWS_WITH_OPENSSL "Compile with OpenSSL support" ON)
option(LIBWS_WITH_LOG "Compile with logging support" ON)
option(LIBWS_WITH_EXAMPLES "Compile with example programs" OFF)
option(LIBWS_EXTERNAL_LOOP "Support marshalling of libevent callbacks")

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/CMakeModules)
find_package(Libevent REQUIRED)


# Set some nicer output dirs.
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

if(${CMAKE_C_COMPILER_ID} STREQUAL "GNU" OR ${CMAKE_C_COMPILER_ID} STREQUAL "Clang")
    add_definitions("-Wall")
endif()

include_directories(${PROJECT_SOURCE_DIR}/src)

set(LIBWS_LIB_LIST ${LIBEVENT_LIBRARIES})
include_directories(${LIBEVENT_INCLUDE_DIRS})

if (WIN32)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_DEPRECATE)
	list(APPEND LIBWS_LIB_LIST Ws2_32.lib iphlpapi.lib User32.lib)
endif()



if (LIBWS_WITH_OPENSSL)
	find_package(OpenSSL REQUIRED)

	if (NOT OPENSSL_FOUND)
		message(FATAL_ERROR "Cannot link OpenSSL not found!")
	endif()

	list(APPEND LIBWS_LIB_LIST 
		${OPENSSL_LIBRARIES}
		${LIBEVENT_OPENSSL_LIBRARY})

	include_directories(${OPENSSL_INCLUDE_DIR})
endif(LIBWS_WITH_OPENSSL)

################################################################################
###                        System introspection                              ###
################################################################################
# //Old MSVC not supported
set(LIBWS_HAVE_STDINT_H 1)
set(LIBWS_HAVE_SYS_TYPES_H 1)
set(LIBWS_HAVE_INTTYPES_H 1)
set(LIBWS_UINT32 uint32_t)
set(LIBWS_UINT64 uint64_t)
set(LIBWS_U64FMT "PRIu64")

if (NOT WIN32)
    set(IS_UNIX 1)
else()
    set(IS_UNIX 0)
endif()

set(LIBWS_HAVE_UNISTD_H ${IS_UNIX})
set(LIBWS_HAVE_SYS_SOCKET_H ${IS_UNIX})
set(LIBWS_HAVE_SYS_TIME_H ${IS_UNIX})
set(LIBWS_INLINE inline)

set(CMAKE_REQUIRED_DEFINITIONS "")

# Generate the config header file.
configure_file(
	"src/libws_config.h.in"
	"${PROJECT_BINARY_DIR}/libws_config.h"
	)

configure_file(
	"src/libws_private_config.h.in"
	"${PROJECT_BINARY_DIR}/libws_private_config.h"
	)

include_directories(${PROJECT_BINARY_DIR})

# Group the sources and headers.
set(SRCS 
	src/libws.c
	src/libws_private.c
	src/libws_header.c
	src/libws_handshake.c
	src/libws_log.c
	src/libws_compat.c
	src/libws_utf8.c)

set(HDRS_PUBLIC 
	src/libws.h
	src/libws_types.h
	src/libws_header.h
	src/libws_log.h)

set(HDRS_PRIVATE
	src/libws_private.h
	src/libws_compat.h
	src/libws_handshake.h
	src/libws_utf8.h
	${PROJECT_BINARY_DIR}/libws_private_config.h)

if (LIBWS_WITH_OPENSSL)
	list(APPEND SRCS src/libws_openssl.c)
	list(APPEND HDRS_PRIVATE src/libws_openssl.h)
else()
	list(APPEND SRCS src/libws_sha1.c)
	list(APPEND HDRS_PRIVATE src/libws_sha1.h)
endif()

source_group("Headers public"	FILES ${HDRS_PUBLIC})
source_group("Headers private"	FILES ${HDRS_PRIVATE})
source_group("Sources"			FILES ${SRCS})

# TODO: Support shared as well.
add_library(ws STATIC 
			${SRCS} 
			${HDRS_PUBLIC} 
			${HDRS_PRIVATE})

# Add libs and dependencies
target_link_libraries(ws ${LIBWS_LIB_LIST})
if (NOT LIBWS_EXTERNAL_LOOP)
    if (LIBWS_WITH_EXAMPLES)
        add_executable(echo_client examples/echo_client/echo_client.c)
        target_link_libraries(echo_client ws)
    endif()
endif()

if (LIBWS_WITH_TESTS)
	ENABLE_TESTING()
	add_subdirectory(test)
endif()

# TODO: Create CMake config.
# TODO: Export libraries and headers.
# TODO: Install stuff
