# Only the sources are gated. REQUIRES is not: ESP-IDF collects component
# requirements during its early-expansion pass, before sdkconfig is read, so a
# CONFIG_-dependent REQUIRES list comes out empty there and the include paths
# go missing even in the build where the feature is on.
if(CONFIG_OLED_DISPLAY)
    set(OLED_SRCS "oled_display.c")
else()
    set(OLED_SRCS "")
endif()

idf_component_register(
    SRCS ${OLED_SRCS}
    INCLUDE_DIRS "include"
    REQUIRES esp_driver_i2c nvs_flash freertos log lwip esp_netif esp_wifi esp_driver_gpio
)
if(OLED_SRCS)
    target_compile_options(${COMPONENT_LIB} PRIVATE -Os)
endif()
