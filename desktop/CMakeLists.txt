cmake_minimum_required(VERSION 3.22)

project(whodis_gui LANGUAGES CXX)

include(GNUInstallDirs)
include(CTest)

set(WHODIS_VERSION "dev" CACHE STRING "Whodis release version")
set(WHODIS_BUNDLE_VERSION "${WHODIS_VERSION}" CACHE STRING "Numeric macOS bundle version")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.2 REQUIRED COMPONENTS Core Gui Widgets)

set(WHODIS_GUI_SOURCES
    src/AdaptiveItemView.cpp
    src/AdaptiveItemView.h
    src/Appearance.cpp
    src/Appearance.h
    src/AdvancedDialog.cpp
    src/AdvancedDialog.h
    src/BatchWindow.cpp
    src/BatchWindow.h
    src/EngineClient.cpp
    src/EngineClient.h
    src/HelpDialog.cpp
    src/HelpDialog.h
    src/MainWindow.cpp
    src/MainWindow.h
    src/ResultWidget.cpp
    src/ResultWidget.h
    src/main.cpp
    resources/resources.qrc
)

qt_add_executable(whodis-gui WIN32 MACOSX_BUNDLE ${WHODIS_GUI_SOURCES})
if(WIN32)
    target_sources(whodis-gui PRIVATE resources/whodis.rc)
endif()
set(WHODIS_MACOS_ICON "" CACHE FILEPATH "Optional generated Whodis .icns file")
if(APPLE AND WHODIS_MACOS_ICON)
    get_filename_component(WHODIS_MACOS_ICON_NAME "${WHODIS_MACOS_ICON}" NAME)
    set_source_files_properties("${WHODIS_MACOS_ICON}" PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")
    target_sources(whodis-gui PRIVATE "${WHODIS_MACOS_ICON}")
    set_target_properties(whodis-gui PROPERTIES MACOSX_BUNDLE_ICON_FILE "${WHODIS_MACOS_ICON_NAME}")
endif()
target_link_libraries(whodis-gui PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets)
target_compile_definitions(whodis-gui PRIVATE WHODIS_GUI_VERSION="${WHODIS_VERSION}")
set_target_properties(whodis-gui PROPERTIES
    OUTPUT_NAME "whodis-gui"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    MACOSX_BUNDLE_BUNDLE_NAME "Whodis"
    MACOSX_BUNDLE_GUI_IDENTIFIER "net.cyberbrand.whodis"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${WHODIS_BUNDLE_VERSION}"
    MACOSX_BUNDLE_BUNDLE_VERSION "${WHODIS_BUNDLE_VERSION}"
)

find_program(GO_EXECUTABLE go REQUIRED)
file(GLOB_RECURSE WHODIS_ENGINE_GO_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/../*.go"
)
if(WIN32)
    set(WHODIS_ENGINE_FILENAME "whodis-gui-engine.exe")
else()
    set(WHODIS_ENGINE_FILENAME "whodis-gui-engine")
endif()
set(WHODIS_ENGINE_OUTPUT "${CMAKE_BINARY_DIR}/bin/${WHODIS_ENGINE_FILENAME}")
add_custom_command(
    OUTPUT "${WHODIS_ENGINE_OUTPUT}"
    COMMAND "${GO_EXECUTABLE}" build -trimpath
            "-ldflags=-s -w -X main.version=${WHODIS_VERSION} -X github.com/Alex9001/whodis/v2.version=${WHODIS_VERSION}"
            -o "${WHODIS_ENGINE_OUTPUT}"
            ./cmd/whodis-gui-engine
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.."
    DEPENDS
        ${WHODIS_ENGINE_GO_SOURCES}
        "${CMAKE_CURRENT_SOURCE_DIR}/../go.mod"
        "${CMAKE_CURRENT_SOURCE_DIR}/../go.sum"
    VERBATIM
)
add_custom_target(whodis-gui-engine ALL DEPENDS "${WHODIS_ENGINE_OUTPUT}")
add_dependencies(whodis-gui whodis-gui-engine)

install(TARGETS whodis-gui
    BUNDLE DESTINATION .
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
if(NOT APPLE)
    if(WIN32)
        install(PROGRAMS "${WHODIS_ENGINE_OUTPUT}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
    else()
        install(PROGRAMS "${WHODIS_ENGINE_OUTPUT}" DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/whodis")
        install(FILES packaging/net.cyberbrand.whodis.desktop DESTINATION "${CMAKE_INSTALL_DATADIR}/applications")
        install(FILES packaging/net.cyberbrand.whodis.metainfo.xml DESTINATION "${CMAKE_INSTALL_DATADIR}/metainfo")
        install(FILES resources/whodis-512.png
            DESTINATION "${CMAKE_INSTALL_DATADIR}/pixmaps"
            RENAME net.cyberbrand.whodis.png)
    endif()
endif()
install(FILES ../LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/whodis-gui")
install(FILES packaging/THIRD_PARTY_NOTICES.md DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/whodis-gui")

if(BUILD_TESTING)
    find_package(Qt6 6.2 REQUIRED COMPONENTS Test)
    qt_add_executable(whodis-gui-tests
        tests/ResultWidgetTest.cpp
        src/AdaptiveItemView.cpp
        src/AdaptiveItemView.h
        src/AdvancedDialog.cpp
        src/AdvancedDialog.h
        src/BatchWindow.cpp
        src/BatchWindow.h
        src/EngineClient.cpp
        src/EngineClient.h
        src/HelpDialog.cpp
        src/HelpDialog.h
        src/MainWindow.cpp
        src/MainWindow.h
        src/ResultWidget.cpp
        src/ResultWidget.h
        resources/resources.qrc
    )
    target_include_directories(whodis-gui-tests PRIVATE src)
    target_compile_definitions(whodis-gui-tests PRIVATE WHODIS_GUI_VERSION="${WHODIS_VERSION}")
    target_link_libraries(whodis-gui-tests PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Test)
    add_test(NAME whodis-gui-widgets COMMAND whodis-gui-tests)
    set_tests_properties(whodis-gui-widgets PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen;WHODIS_GUI_ENGINE=${WHODIS_ENGINE_OUTPUT}")

    qt_add_executable(whodis-gui-appearance-tests
        tests/AppearanceTest.cpp
        src/Appearance.cpp
        src/Appearance.h
    )
    target_include_directories(whodis-gui-appearance-tests PRIVATE src)
    target_link_libraries(whodis-gui-appearance-tests PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Test)
    add_test(NAME whodis-gui-appearance COMMAND whodis-gui-appearance-tests)
    set_tests_properties(whodis-gui-appearance PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endif()
