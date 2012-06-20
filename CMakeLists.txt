CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(libprivilege-control C)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")
SET(VERSION 1.0)

SET(VERSION_MAJOR 0)
SET(VERSION "${VERSION_MAJOR}.0.2")

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED security-server openssl)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(src_dir "./src")
SET(include_dir "./include")

## Additional flag
SET(activate "-DUSE_PRIVILEGE_CONTROL")

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

###################################################################################################
## for libprivilege-control.so (library)
SET(libprivilege-control_SOURCES ${src_dir}/privilege-control.c ${src_dir}/account-manage.c)
SET(libprivilege-control_LDFLAGS " -module -avoid-version ")
SET(libprivilege-control_CFLAGS  " ${CFLAGS} -fPIC -I${include_dir} ${activate} ")
#SET(libprivilege-control_LIBADD " ")

ADD_LIBRARY(privilege-control SHARED ${libprivilege-control_SOURCES})
TARGET_LINK_LIBRARIES(privilege-control ${pkgs_LDFLAGS})
SET_TARGET_PROPERTIES(privilege-control PROPERTIES COMPILE_FLAGS "${libprivilege-control_CFLAGS}")
SET_TARGET_PROPERTIES(privilege-control PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(privilege-control PROPERTIES VERSION ${VERSION})
###################################################################################################

###################################################################################################
## for slp-su (excutable)
SET(slp-su_SOURCES ${src_dir}/slp-su.c)
SET(slp-su_LDFLAGS " -module -avoid-version ")
SET(slp-su_CFLAGS  " ${CFLAGS} -fPIC -I${include_dir} ${activate} ")

ADD_EXECUTABLE(slp-su ${slp-su_SOURCES})
TARGET_LINK_LIBRARIES(slp-su ${pkgs_LDFLAGS} privilege-control)
SET_TARGET_PROPERTIES(slp-su PROPERTIES COMPILE_FLAGS "${slp-su_CFLAGS}")
###################################################################################################

###################################################################################################
## for debug-util (excutable)
SET(debug-util_SOURCES ${src_dir}/debug-util.c)
SET(debug-util_LDFLAGS " -module -avoid-version ")
SET(debug-util_CFLAGS  " ${CFLAGS} -fPIC -I${include_dir} ${activate} ")

ADD_EXECUTABLE(debug-util ${debug-util_SOURCES})
TARGET_LINK_LIBRARIES(debug-util ${pkgs_LDFLAGS} privilege-control)
SET_TARGET_PROPERTIES(debug-util PROPERTIES COMPILE_FLAGS "${debug-util_CFLAGS}")
###################################################################################################

###################################################################################################
## for kill_app (excutable)
SET(kill-app_SOURCES ${src_dir}/kill_app.c)
SET(kill-app_LDFLAGS " -module -avoid-version ")
SET(kill-app_CFLAGS  " ${CFLAGS} -fPIC -I${include_dir} ${activate} ")

ADD_EXECUTABLE(kill_app ${kill-app_SOURCES})
#TARGET_LINK_LIBRARIES(kill_app ${pkgs_LDFLAGS} privilege-control)
SET_TARGET_PROPERTIES(kill_app PROPERTIES COMPILE_FLAGS "${kill-app_CFLAGS}")
###################################################################################################

CONFIGURE_FILE(libprivilege-control.pc.in libprivilege-control.pc @ONLY)

FILE(GLOB datfiles ${CMAKE_CURRENT_SOURCE_DIR}/permissions/*.dat)
FILE(GLOB udevfiles ${CMAKE_CURRENT_SOURCE_DIR}/udev/rules/*)

INSTALL(TARGETS privilege-control DESTINATION lib COMPONENT RuntimeLibraries)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/libprivilege-control.pc DESTINATION lib/pkgconfig)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/passwd DESTINATION /opt/etc/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/group DESTINATION /opt/etc/)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/privilege-control.h DESTINATION include)
INSTALL(FILES ${datfiles} DESTINATION /usr/share/privilege-control)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/app_group_list DESTINATION /usr/share/privilege-control)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/dev_group_list DESTINATION /usr/share/privilege-control)
INSTALL(FILES ${udevfiles} DESTINATION ${LIBDIR}/udev/rules.d)
INSTALL(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/slp-su DESTINATION bin)
INSTALL(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/debug-util DESTINATION bin)
INSTALL(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/kill_app DESTINATION bin)
