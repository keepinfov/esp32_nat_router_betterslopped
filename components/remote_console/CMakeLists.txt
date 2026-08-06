# Only the sources are gated. REQUIRES is not: ESP-IDF collects component
# requirements during its early-expansion pass, before sdkconfig is read, so a
# CONFIG_-dependent REQUIRES list comes out empty there and the include paths
# go missing even in the build where the feature is on.
# See components/syslog/CMakeLists.txt for the compile-options guard.
if(CONFIG_REMOTE_CONSOLE)
    set(RC_SRCS "remote_console.c")
else()
    set(RC_SRCS "")
endif()

idf_component_register(
    SRCS ${RC_SRCS}
    INCLUDE_DIRS "include"
    REQUIRES esp_timer nvs_flash console lwip esp_netif esp_event log cmd_router
)

if(RC_SRCS)
    target_compile_options(${COMPONENT_LIB} PRIVATE -Os)

    # Wrap output functions to intercept console output.
    # Note: do NOT wrap vprintf — ESP_LOG uses it internally.
    # These belong with the sources: with nothing to wrap to, the wrappers
    # would leave every printf resolving to __wrap_printf and fail to link.
    target_link_libraries(${COMPONENT_LIB} INTERFACE
        "-Wl,--wrap=printf"
        "-Wl,--wrap=puts"
        "-Wl,--wrap=putchar"
        "-Wl,--wrap=fputs"
        "-Wl,--wrap=fwrite"
    )
endif()
