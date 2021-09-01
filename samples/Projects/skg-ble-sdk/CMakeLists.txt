cmake_minimum_required(VERSION 3.13.1)

# Add the cmake folder so the FindSphinx module is found
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

set(SKGBLESDK_ROOT_DIR          ${CMAKE_CURRENT_SOURCE_DIR})
set(SKGBLESDK_INCLUDE_DIR       ${SKGBLESDK_ROOT_DIR}/include)
set(SKGBLESDK_LIB_DIR           ${CMAKE_CURRENT_SOURCE_DIR}/lib)

set(SKGCORELIB_SRC_DIR          ${SKGBLESDK_LIB_DIR}/core)
set(SKGCORELIB_INCLUDE_DIR      ${SKGBLESDK_LIB_DIR}/core/include)
set(SKGCORELIB_BUILD_DIR        ${CMAKE_CURRENT_BINARY_DIR}/skgcorelib)
set(SKGCORELIB_LIB_DIR          ${SKGCORELIB_BUILD_DIR}/src)

set (WIOLINK_SAMPLES_NUM 4)
set (QUAN_MEAN_MIN -110)
set (WIOLINK_SKG_KEY_MULT_NUMERATOR 1)
set (WIOLINK_SKG_KEY_MULT_DENOMINATOR 1)

set (FLAGS "")

if (MAX_CONCURRENT_CHALLENGES)
	list(APPEND FLAGS "-DMAX_CONCURRENT_CHALLENGES=${MAX_CONCURRENT_CHALLENGES}")
	add_compile_definitions(MAX_CONCURRENT_CHALLENGES=${MAX_CONCURRENT_CHALLENGES})
endif()

list(APPEND FLAGS "-DWIOLINK_SAMPLES_NUM=${WIOLINK_SAMPLES_NUM}")
add_compile_definitions(WIOLINK_TRX_POWER_NUM=${WIOLINK_SAMPLES_NUM})
add_compile_definitions(QUAN_SAMPLES_NUM=${WIOLINK_SAMPLES_NUM})
add_compile_definitions(KEY_MAX_SAMPLE_BLOCK=${WIOLINK_SAMPLES_NUM})

list(APPEND FLAGS "-DWIOLINK_SKG_KEY_MULT_NUMERATOR=${WIOLINK_SKG_KEY_MULT_NUMERATOR}")
add_compile_definitions(WIOLINK_SKG_KEY_MULT_NUMERATOR=${WIOLINK_SKG_KEY_MULT_NUMERATOR})

list(APPEND FLAGS "-DWIOLINK_SKG_KEY_MULT_DENOMINATOR=${WIOLINK_SKG_KEY_MULT_DENOMINATOR}")
add_compile_definitions(WIOLINK_SKG_KEY_MULT_DENOMINATOR=${WIOLINK_SKG_KEY_MULT_DENOMINATOR})

list(APPEND FLAGS "-DQUAN_MEAN_MIN=${QUAN_MEAN_MIN}")
add_compile_definitions(QUAN_MEAN_MIN=${QUAN_MEAN_MIN})

if (WIOLINK_TRX_FREQ_NUM)
	list(APPEND FLAGS "-DWIOLINK_TRX_FREQ_NUM=${WIOLINK_TRX_FREQ_NUM}")
	add_compile_definitions(WIOLINK_TRX_FREQ_NUM=${WIOLINK_TRX_FREQ_NUM})
endif()

message(STATUS "FLAGS:" ${FLAGS})

include(ExternalProject)
ExternalProject_Add(
	skgcorelib_project
	SOURCE_DIR        ${SKGCORELIB_SRC_DIR}
	BINARY_DIR        ${SKGCORELIB_BUILD_DIR}
	DOWNLOAD_COMMAND  ""
	CMAKE_ARGS        "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}"
			  "-DCMAKE_AR=${CMAKE_AR}"
			  "-DCMAKE_C_FLAGS=${external_project_cflags}"
			  "-DBUILD_MINIMAL_LIB=ON"
			  "-DHOST_NATIVE_TESTS=OFF"
			  "-DCMAKE_C_COMPILER_FORCED=ON"
			  "-DBUILD_SHARED_LIBS=OFF"
			  "${FLAGS}"
	LOG_BUILD         ON
	INSTALL_COMMAND   ""
	BUILD_BYPRODUCTS  ${SKGCORELIB_LIB_DIR}/libskgcore.a ${SKGCORELIB_LIB_DIR}/libtinymt32.a
)

add_library(skgcorelib STATIC IMPORTED)
add_dependencies(
	skgcorelib
	skgcorelib_project
)
set_target_properties(skgcorelib PROPERTIES IMPORTED_LOCATION
		      ${SKGCORELIB_LIB_DIR}/libskgcore.a)
set_target_properties(skgcorelib PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
		      ${SKGCORELIB_INCLUDE_DIR})

add_library(tinymt32lib STATIC IMPORTED)
add_dependencies(
	tinymt32lib
	skgcorelib_project
)
set_target_properties(tinymt32lib PROPERTIES IMPORTED_LOCATION
		      ${SKGCORELIB_LIB_DIR}/libtinymt32.a)
set_target_properties(tinymt32lib PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                      ${SKGCORELIB_INCLUDE_DIR})

add_subdirectory(${SKGBLESDK_LIB_DIR}/bluetooth_dap)
set(DAP_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/lib/bluetooth_dap)

# Now we need to bundle the three libs together to form the SDK
set(SDK_LIB ${CMAKE_BINARY_DIR}/libskgblesdk.a)
add_custom_command(OUTPUT ${SDK_LIB}
	COMMAND ${CMAKE_AR} -x ${SKGCORELIB_LIB_DIR}/libskgcore.a
	COMMAND ${CMAKE_AR} -x ${SKGCORELIB_LIB_DIR}/libtinymt32.a
	COMMAND ${CMAKE_AR} -x ${DAP_LIB_DIR}/libbledap.a
	COMMAND ${CMAKE_AR} -qcs ${SDK_LIB} *.o*
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	DEPENDS skgcorelib tinymt32lib bledap
	COMMENT "Bundling the SDK as ${SDK_LIB}"
)
add_custom_target(sdkbundle DEPENDS ${SDK_LIB})

add_library(skgblesdk STATIC IMPORTED GLOBAL)
add_dependencies(skgblesdk sdkbundle)
set_target_properties(skgblesdk PROPERTIES IMPORTED_LOCATION ${SDK_LIB})
target_include_directories(skgblesdk INTERFACE ${SKGBLESDK_INCLUDE_DIR})

add_subdirectory(docs)
