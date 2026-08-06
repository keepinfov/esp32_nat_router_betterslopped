# Only the sources are gated. REQUIRES is not: ESP-IDF collects component
# requirements during its early-expansion pass, before sdkconfig is read, so a
# CONFIG_-dependent REQUIRES list comes out empty there and the include paths
# go missing even in the build where the feature is on.
# See components/syslog/CMakeLists.txt for the compile-options guard.
if(CONFIG_PCAP_CAPTURE)
    set(PCAP_SRCS "pcap_capture.c" "pcap_ringbuf.c")
else()
    set(PCAP_SRCS "")
endif()

idf_component_register(SRCS ${PCAP_SRCS}
                    INCLUDE_DIRS "include"
                    REQUIRES lwip freertos esp_timer)

if(PCAP_SRCS)
    target_compile_options(${COMPONENT_LIB} PRIVATE -O2)
endif()
