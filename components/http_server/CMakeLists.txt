idf_component_register(
    SRCS "http_server.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES esp_http_server esp_wifi esp_netif esp_event nvs_flash
                  esp_timer json cmd_router acl pcap_capture
                  remote_console dhcpserver wpa_supplicant
                  app_update esp_app_format mbedtls
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-function -Os)

# Static web assets are minified and stored gzipped, then served with
# Content-Encoding: gzip, so the stylesheet costs about 1.3 KB of flash instead
# of the ~24 KB it took as seven copies of an inline <style> block.
#
# Minifying at build time is what lets the sources in www/ keep their comments
# and indentation: those explain the design decisions but would otherwise cost
# roughly 1.5 KB of the OTA slot.
#
# The work runs through Python rather than shell tools because ESP-IDF always
# ships a Python interpreter and Windows hosts often have neither gzip nor a
# minifier. target_add_binary_data is used instead of EMBED_FILES because the
# inputs are generated at build time and so do not exist when CMake configures.
set(WWW_ASSETS app.css app.js favicon.svg)
set(PACK_ASSET "${COMPONENT_DIR}/pack_asset.py")

foreach(asset ${WWW_ASSETS})
    set(gz "${CMAKE_CURRENT_BINARY_DIR}/${asset}.gz")
    add_custom_command(
        OUTPUT "${gz}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}"
        COMMAND ${python} "${PACK_ASSET}" "${COMPONENT_DIR}/www/${asset}" "${gz}"
        DEPENDS "${COMPONENT_DIR}/www/${asset}" "${PACK_ASSET}"
        COMMENT "Packing ${asset}"
        VERBATIM)
    list(APPEND WWW_GZ "${gz}")
endforeach()

add_custom_target(www_gz DEPENDS ${WWW_GZ})

foreach(gz ${WWW_GZ})
    target_add_binary_data(${COMPONENT_LIB} "${gz}" BINARY DEPENDS www_gz)
endforeach()
