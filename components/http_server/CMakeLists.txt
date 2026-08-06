idf_component_register(
    SRCS "http_server.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES esp_http_server esp_wifi esp_netif esp_event nvs_flash
                  esp_timer json cmd_router acl pcap_capture
                  remote_console dhcpserver wpa_supplicant
                  app_update esp_app_format mbedtls
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-function -Os)

# Static web assets are stored gzipped and served with Content-Encoding: gzip,
# so the stylesheet costs about 2 KB of flash instead of the ~24 KB it took as
# seven copies of an inline <style> block.
#
# Compression runs through Python rather than the gzip binary because ESP-IDF
# always ships a Python interpreter and Windows hosts often have no gzip.
# target_add_binary_data is used instead of EMBED_FILES because the inputs are
# generated at build time and so do not exist when CMake configures.
set(WWW_ASSETS app.css app.js favicon.svg)

foreach(asset ${WWW_ASSETS})
    set(gz "${CMAKE_CURRENT_BINARY_DIR}/${asset}.gz")
    add_custom_command(
        OUTPUT "${gz}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}"
        COMMAND ${python} -c
            "import gzip,sys; open(sys.argv[2],'wb').write(gzip.compress(open(sys.argv[1],'rb').read(),9,mtime=0))"
            "${COMPONENT_DIR}/www/${asset}" "${gz}"
        DEPENDS "${COMPONENT_DIR}/www/${asset}"
        COMMENT "Compressing ${asset}"
        VERBATIM)
    list(APPEND WWW_GZ "${gz}")
endforeach()

add_custom_target(www_gz DEPENDS ${WWW_GZ})

foreach(gz ${WWW_GZ})
    target_add_binary_data(${COMPONENT_LIB} "${gz}" BINARY DEPENDS www_gz)
endforeach()
