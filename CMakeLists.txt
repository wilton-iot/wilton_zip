
cmake_minimum_required ( VERSION 2.8.12 )

# project
project ( wilton_zip CXX )

# dependencies add
if ( STATICLIB_TOOLCHAIN MATCHES "(android|windows|macosx)_.+" )
    staticlib_add_subdirectory ( ${STATICLIB_DEPS}/external_zlib )
endif ( )
staticlib_add_subdirectory ( ${STATICLIB_DEPS}/staticlib_endian )
staticlib_add_subdirectory ( ${STATICLIB_DEPS}/staticlib_compress )
staticlib_add_subdirectory ( ${STATICLIB_DEPS}/staticlib_unzip )

# dependencies check
set ( ${PROJECT_NAME}_DEPS
        staticlib_config
        staticlib_support
        staticlib_io
        staticlib_endian
        staticlib_compress
        staticlib_utils
        staticlib_json
        staticlib_tinydir
        staticlib_unzip
        zlib )
staticlib_pkg_check_modules ( ${PROJECT_NAME}_DEPS_PC REQUIRED ${PROJECT_NAME}_DEPS )

# library
set ( ${PROJECT_NAME}_PLATFORM_SRC ) 
set ( ${PROJECT_NAME}_RESFILE )
set ( ${PROJECT_NAME}_DEFFILE )
if ( STATICLIB_TOOLCHAIN MATCHES "windows_.+" )
    configure_file ( ${WILTON_DIR}/resources/buildres/wilton_module.rc
            ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.rc )
    set ( ${PROJECT_NAME}_RESFILE ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.rc )
    set ( ${PROJECT_NAME}_DEFFILE ${CMAKE_CURRENT_LIST_DIR}/resources/${PROJECT_NAME}.def )
endif ( )

add_library ( ${PROJECT_NAME} SHARED
        ${CMAKE_CURRENT_LIST_DIR}/src/wiltoncall_zip.cpp
        ${${PROJECT_NAME}_RESFILE}
        ${${PROJECT_NAME}_DEFFILE} )
        
target_link_libraries ( ${PROJECT_NAME} PRIVATE
        wilton_core
        wilton_logging
        ${${PROJECT_NAME}_DEPS_PC_LIBRARIES} )

target_include_directories ( ${PROJECT_NAME} BEFORE PRIVATE 
        ${CMAKE_CURRENT_LIST_DIR}/src
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${WILTON_DIR}/core/include
        ${WILTON_DIR}/modules/wilton_logging/include
        ${${PROJECT_NAME}_DEPS_PC_INCLUDE_DIRS} )
        
target_compile_options ( ${PROJECT_NAME} PRIVATE ${${PROJECT_NAME}_DEPS_PC_CFLAGS_OTHER} )

if ( STATICLIB_TOOLCHAIN MATCHES "android_.+" )
    set_property ( TARGET ${PROJECT_NAME} APPEND_STRING PROPERTY LINK_FLAGS "-Wl,-soname,lib${PROJECT_NAME}.so" )
    get_property ( ${PROJECT_NAME}_LINK_FLAGS TARGET ${PROJECT_NAME} PROPERTY LINK_FLAGS )
    set_property ( TARGET ${PROJECT_NAME} PROPERTY LINK_FLAGS
            "-Wl,--whole-archive ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libz.a -Wl,--no-whole-archive ${${PROJECT_NAME}_LINK_FLAGS}" )
elseif ( STATICLIB_TOOLCHAIN MATCHES "windows_.+" )
    target_link_libraries ( ${PROJECT_NAME} PRIVATE wtsapi32 )
    set_property ( TARGET ${PROJECT_NAME} APPEND_STRING PROPERTY LINK_FLAGS "/manifest:no" )
endif ( )

# pkg-config
set ( ${PROJECT_NAME}_PC_CFLAGS "-I${CMAKE_CURRENT_LIST_DIR}/include" )
set ( ${PROJECT_NAME}_PC_LIBS "-L${CMAKE_LIBRARY_OUTPUT_DIRECTORY} -l${PROJECT_NAME}" )
staticlib_list_to_string ( ${PROJECT_NAME}_PC_REQUIRES_PRIVATE "" ${PROJECT_NAME}_DEPS )
configure_file ( ${WILTON_DIR}/resources/buildres/pkg-config.in 
        ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/pkgconfig/${PROJECT_NAME}.pc )
