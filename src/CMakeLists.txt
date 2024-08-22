# SPDX-License-Identifier: Apache-2.0
message(STATUS "Vertices SDK location: ${CMAKE_CURRENT_SOURCE_DIR}")

set(VERTICES_SRC_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/account.c
        ${CMAKE_CURRENT_SOURCE_DIR}/account_storage.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mnemonic.c
        ${CMAKE_CURRENT_SOURCE_DIR}/utils/base64.c
        ${CMAKE_CURRENT_SOURCE_DIR}/utils/base32.c
        ${CMAKE_CURRENT_SOURCE_DIR}/utils/base2048.c
        ${CMAKE_CURRENT_SOURCE_DIR}/utils/http_weak.c
        ${CMAKE_CURRENT_SOURCE_DIR}/utils/sha512_256.c
        ${CMAKE_CURRENT_SOURCE_DIR}/utils/secretbox.c
        ${CMAKE_CURRENT_SOURCE_DIR}/vertices_errors.c
        ${CMAKE_CURRENT_SOURCE_DIR}/vertices.c
        ${CMAKE_CURRENT_SOURCE_DIR}/algorand/algorand_parser.c
        ${CMAKE_CURRENT_SOURCE_DIR}/algorand/algorand_provider.c
        ${CMAKE_CURRENT_SOURCE_DIR}/algorand/algorand_transaction.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../external/mpack/src/mpack/mpack-common.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../external/mpack/src/mpack/mpack-reader.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../external/mpack/src/mpack/mpack-platform.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../external/mpack/src/mpack/mpack-expect.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../external/mpack/src/mpack/mpack-node.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../external/mpack/src/mpack/mpack-writer.c
)

set(VERTICES_INC_DIRS
        "include"
        "../external/cJSON"
        "../external/mpack/src/mpack"
        )

# add_definitions(-DSRC_CONFIG_PATH="${CMAKE_CURRENT_SOURCE_DIR}/config/")

string(LENGTH "${CMAKE_SOURCE_DIR}/" SOURCE_PATH_SIZE)

if( NOT DEFINED BUILT_TARGET )
    set(BUILT_TARGET "NONE")
endif()

if( NOT DEFINED VERTICES_TYPE )
    set(VERTICES_TYPE "SHARED")
endif()

if( ${VERTICES_TYPE} STREQUAL "SHARED" )
    set(UNREAL_SDK_PATH "C:/Users/Conan Exiles/Documents/Unreal Projects")
    set(UNREAL_SDK_PROJECT "unreal-algorand-demo")
    set(HEADER_FILES_TO_COPY
            "../include/vertices.h->${UNREAL_SDK_PROJECT}/Plugins/Algorand/Source/Vertices/Public/include/vertices/vertices.h"
            "../include/vertices_config.h->${UNREAL_SDK_PROJECT}/Plugins/Algorand/Source/Vertices/Public/include/vertices/vertices_config.h"
            "../include/vertices_errors.h->${UNREAL_SDK_PROJECT}/Plugins/Algorand/Source/Vertices/Public/include/vertices/vertices_errors.h"
            "../include/vertices_http.h->${UNREAL_SDK_PROJECT}/Plugins/Algorand/Source/Vertices/Public/include/vertices/vertices_http.h"
            "../include/vertices_types.h->${UNREAL_SDK_PROJECT}/Plugins/Algorand/Source/Vertices/Public/include/vertices/vertices_types.h"
            "include/vertices_log.h->${UNREAL_SDK_PROJECT}/Plugins/Algorand/Source/Vertices/Public/include/vertices_log.h"
            "include/utils/base32.h->${UNREAL_SDK_PROJECT}/Plugins/Algorand/Source/Vertices/Public/include/utils/base32.h"
            "include/utils/base64.h->${UNREAL_SDK_PROJECT}/Plugins/Algorand/Source/Vertices/Public/include/utils/base64.h"
            "include/utils/base2048.h->${UNREAL_SDK_PROJECT}/Plugins/Algorand/Source/Vertices/Public/include/utils/base2048.h"
            "include/utils/sha512_256.h->${UNREAL_SDK_PROJECT}/Plugins/Algorand/Source/Vertices/Public/include/utils/sha512_256.h"
    )
endif ()

if (COMPILE_UNIX)
    add_definitions("-DSOURCE_PATH_SIZE=${SOURCE_PATH_SIZE}")

    if( ${VERTICES_TYPE} STREQUAL STATIC )
        add_library(vertices STATIC ${VERTICES_SRC_FILES})
    else()
        add_library(vertices SHARED ${VERTICES_SRC_FILES})
    endif()

    set_target_properties( vertices
            PROPERTIES
            ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
            )

    if( ${VERTICES_TYPE} STREQUAL SHARED )
        #copy vertices library to vs 2019 unreal plugin
        add_custom_command(TARGET vertices POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_BINARY_DIR}/bin
                ${UNREAL_SDK_PATH}/${UNREAL_SDK_PROJECT}/Plugins/Algorand/Binaries/ThirdParty/AlgorandLibrary/Win64
                COMMENT "Copying vertices.dll from cmake_bin folder to ue binary one"
                COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_BINARY_DIR}/lib
                ${UNREAL_SDK_PATH}/${UNREAL_SDK_PROJECT}/Plugins/Algorand/Source/ThirdParty/AlgorandLibrary/x64/Release
                COMMENT "Copying vertices.lib from cmake_bin folder to ue 3rd-party release one"
                COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_BINARY_DIR}/bin
                ${UNREAL_SDK_PATH}/${UNREAL_SDK_PROJECT}/Plugins/Algorand/Source/ThirdParty/AlgorandLibrary/x64/Release
                COMMENT "Copying vertices.dll from cmake_bin folder to ue 3rd-party release one")

        foreach(file_pair ${HEADER_FILES_TO_COPY})
            string(REPLACE "->" ";" file_pair_split ${file_pair})
            list(LENGTH file_pair_split num_pair_list)

            # Validate the pair split correctly into exactly 2 items
            if(num_pair_list EQUAL 2)
                list(GET file_pair_split 0 src_file)
                list(GET file_pair_split 1 dest_file)

                add_custom_command(
                        TARGET vertices POST_BUILD
                        COMMAND ${CMAKE_COMMAND} -E copy
                        ${CMAKE_CURRENT_SOURCE_DIR}/${src_file}
                        ${UNREAL_SDK_PATH}/${dest_file}
                        COMMENT "Copying ${src_file} to ${dest_file}"
                )
            endif ()
        endforeach()

        add_custom_command(TARGET vertices POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_BINARY_DIR}/bin
                ${CMAKE_BINARY_DIR}/../../walletStorage/dll
                COMMENT "Copying vertices.dll from cmake_bin folder to wallet storage one"
                COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_BINARY_DIR}/lib
                ${CMAKE_BINARY_DIR}/../../walletStorage/dll
                COMMENT "Copying vertices.lib from cmake_bin folder to ue wallet storage release one")
    endif()

    target_include_directories(vertices
            PUBLIC
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/utils>"
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>"
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../external/cJSON>"
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../external/mbedtls/library>"
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../external/ed25519>"
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../external/mpack/src/mpack>"
            "$<INSTALL_INTERFACE:../include>"
            )

    # public header files
    install(FILES ../include/vertices.h ../include/vertices_errors.h ../include/vertices_types.h ../include/vertices_http.h DESTINATION include)

    install(TARGETS vertices
            EXPORT verticesTargets
            LIBRARY DESTINATION lib
            ARCHIVE DESTINATION lib
            RUNTIME DESTINATION bin
            INCLUDES DESTINATION include
            )

    if( ${BUILT_TARGET} STREQUAL vertices )
        if(MSVC OR MSYS OR MINGW)
            set(libsodium_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/libs/sodium/include")
            include_directories(${libsodium_INCLUDE_DIRS})

            add_library( sodium STATIC IMPORTED )
            set_target_properties( sodium PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/libs/sodium/x64/libsodium.lib )
            target_link_libraries(vertices cjson mbedcrypto sodium)
        elseif(UNIX AND NOT APPLE)
            target_link_libraries(vertices cjson mbedcrypto)
            target_compile_options(vertices PRIVATE -pedantic -Wall -Wstrict-prototypes -Wwrite-strings -Wshadow -Winit-self -Wformat=2 -Wmissing-prototypes -Wstrict-overflow=2 -Wc++-compat -Wundef -Wconversion -Wno-missing-braces)
        else()  # MacOS

        endif()
    else()
        target_link_libraries(vertices cjson mbedcrypto)
        target_compile_options(vertices PRIVATE -pedantic -Wall -Wstrict-prototypes -Wwrite-strings -Wshadow -Winit-self -Wformat=2 -Wmissing-prototypes -Wstrict-overflow=2 -Wc++-compat -Wundef -Wconversion -Wno-missing-braces)
    endif()

else ()
    target_compile_options(mbedcrypto PRIVATE -DMBEDTLS_CONFIG_FILE=<${CMAKE_CURRENT_SOURCE_DIR}/include/mbedtls_config.h>)

    add_library(vertices STATIC ${VERTICES_SRC_FILES})
    target_include_directories(vertices PUBLIC ../include PRIVATE ${VERTICES_INC_DIRS})

    target_link_libraries(vertices cjson mbedcrypto)
endif ()