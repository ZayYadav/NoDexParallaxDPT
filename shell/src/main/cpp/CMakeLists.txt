cmake_minimum_required(VERSION 3.31.1)

project("parallax")

set(PARALLAX_NATIVE_SOURCE
        parallax_bootstrap.cpp
        parallax.cpp
        parallax_hook.cpp
        parallax_jni.cpp
        parallax_util.cpp
        parallax_risk.cpp
        parallax_crypto.cpp
        parallax_hardening.cpp
        parallax_runtime_guard.cpp
        parallax_policy.cpp
        parallax_vm.cpp
        parallax_vm_exports.cpp
        rc4/rc4.c
        common/parallax_string.c
        dex/dex_file.cpp
        dex/MultiDexCode.cpp
        dex/CodeItem.cpp
        reflect/dalvik_system_BaseDexClassLoader.cpp
        reflect/dalvik_system_DexPathList.cpp
        reflect/java_io_File.cpp
        reflect/java_util_ArrayList.cpp
        reflect/java_lang_Class.cpp
        reflect/android_app_ActivityThread.cpp
        reflect/android_content_pm_ApplicationInfo.cpp
        reflect/android_app_Application.cpp
        reflect/android_app_LoadedApk.cpp
        reflect/android_app_ContextImpl.cpp
        )

set(MZ_LZMA OFF CACHE BOOL "" FORCE)
set(MZ_ZSTD OFF CACHE BOOL "" FORCE)
set(MZ_OPENSSL OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)

add_subdirectory(external/mbedtls)
include_directories(external/mbedtls/include)

if(TARGET MbedTLS::mbedcrypto)
    set(PARALLAX_MBEDCRYPTO_TARGET MbedTLS::mbedcrypto)
elseif(TARGET mbedcrypto)
    set(PARALLAX_MBEDCRYPTO_TARGET mbedcrypto)
else()
    message(FATAL_ERROR "Mbed TLS crypto target was not created")
endif()

file(GLOB BHOOK_SOURCE external/bhook/bytehook/src/main/cpp/*.c)
add_library(bytehook STATIC ${BHOOK_SOURCE})
target_include_directories(bytehook PUBLIC
        external/bhook/bytehook/src/main/cpp
        external/bhook/bytehook/src/main/cpp/include
        external/bhook/bytehook/src/main/cpp/third_party/bsd
        external/bhook/bytehook/src/main/cpp/third_party/lss)
target_link_libraries(bytehook log)

add_subdirectory(external/minizip-ng)

if(NOT TARGET dobby)
    set(DOBBY_DIR external/Dobby)
    macro(SET_OPTION option value)
        set(${option} ${value} CACHE INTERNAL "" FORCE)
    endmacro()
    SET_OPTION(DOBBY_DEBUG OFF)
    SET_OPTION(DOBBY_GENERATE_SHARED OFF)
    add_definitions(-DLOGGING_DISABLE)
    add_subdirectory(${DOBBY_DIR} dobby)
    get_property(DOBBY_INCLUDE_DIRECTORIES TARGET dobby PROPERTY INCLUDE_DIRECTORIES)
    include_directories(
            .
            ${DOBBY_INCLUDE_DIRECTORIES}
            $<TARGET_PROPERTY:dobby,INCLUDE_DIRECTORIES>
    )
endif()

add_definitions(-DDECRYPT_BITCODE)

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    add_definitions(-DDEBUG)
    message(WARNING "!!!WARNNING:opened log!!!")
else()
    set(OPTIMIZATION_LEVEL "-Oz")
    set(PARALLAX_RELEASE_COMMON "-fvisibility=hidden -ffunction-sections -fdata-sections -fstack-protector-strong -fno-common -ftrivial-auto-var-init=zero -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -DNDEBUG -ffile-prefix-map=${CMAKE_SOURCE_DIR}=. ${OPTIMIZATION_LEVEL}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${PARALLAX_RELEASE_COMMON}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${PARALLAX_RELEASE_COMMON} -fvisibility-inlines-hidden")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--exclude-libs,ALL -Wl,--gc-sections -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/parallax.exports.map")
    message("release hardening: hidden visibility, stack protector, FORTIFY, RELRO/NOW, NX stack, section GC")
endif()

message("so name: ${SO_NAME}")

if(NOT DEFINED PARALLAX_BUILD_KEY OR PARALLAX_BUILD_KEY STREQUAL "")
    message(FATAL_ERROR "PARALLAX_BUILD_KEY is required")
endif()
# Never print PARALLAX_BUILD_KEY: it is intentionally kept out of CI logs.

add_compile_definitions(JNI_BRIDGE_NAME="${JNI_BRIDGE_NAME}")
add_compile_definitions(SO_NAME="${SO_NAME}.so")
add_compile_definitions(PARALLAX_BUILD_KEY="${PARALLAX_BUILD_KEY}")

include_directories(./ )
include_directories(./common)

add_library(${SO_NAME} SHARED ${PARALLAX_NATIVE_SOURCE})
set_target_properties(${SO_NAME} PROPERTIES PREFIX "")

# Release logging is compiled out, so delayMs in scheduleExit() is intentionally
# unused in parallax_risk.cpp. Keep -Werror globally, but suppress only this
# source-local false positive instead of weakening warnings for the whole target.
set_source_files_properties(parallax_risk.cpp PROPERTIES COMPILE_OPTIONS "-Wno-unused-parameter")

find_library(log-lib log)
find_library(android-lib android)
find_library(z-lib z)

if(NOT z-lib)
    message(FATAL_ERROR "Android zlib is required for compressed PCI3 method vaults")
endif()

target_compile_options(${SO_NAME} PRIVATE
        -Wall
        -Wextra
        -Werror
        -Wformat
        -Wformat-security
)
target_link_options(${SO_NAME} PRIVATE
        "-Wl,-z,max-page-size=16384"
        "-Wl,--script=${CMAKE_CURRENT_SOURCE_DIR}/parallax_sections.ld")
set_property(TARGET ${SO_NAME} APPEND PROPERTY LINK_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/parallax_sections.ld")

target_link_libraries(${SO_NAME}
        ${log-lib}
        MINIZIP::minizip
        dobby
        bytehook
        ${android-lib}
        ${z-lib}
        ${PARALLAX_MBEDCRYPTO_TARGET}
)

ENABLE_LANGUAGE(ASM)