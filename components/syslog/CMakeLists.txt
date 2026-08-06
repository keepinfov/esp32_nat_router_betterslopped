# Only the sources are gated. REQUIRES is not: ESP-IDF collects component
# requirements during its early-expansion pass, before sdkconfig is read, so a
# CONFIG_-dependent REQUIRES list comes out empty there and the include paths
# go missing even in the build where the feature is on.
#
# A component registered with no sources becomes an INTERFACE target, and
# PRIVATE compile options on one are a CMake error — hence the second guard.
if(CONFIG_SYSLOG_CLIENT)
    set(SYSLOG_SRCS "syslog_client.c")
else()
    set(SYSLOG_SRCS "")
endif()

idf_component_register(
    SRCS ${SYSLOG_SRCS}
    INCLUDE_DIRS "include" "${CMAKE_SOURCE_DIR}/include"
    REQUIRES lwip nvs_flash log esp_netif
)

if(SYSLOG_SRCS)
    target_compile_options(${COMPONENT_LIB} PRIVATE -Os)
endif()
