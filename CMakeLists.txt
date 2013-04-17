CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(libprivilege-control C)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(SHAREDIR "${PREFIX}/share/privilege-control")
SET(HOMEDIR "/opt/home")
SET(VERSION 1.0)

SET(VERSION_MAJOR 0)
SET(VERSION "${VERSION_MAJOR}.0.2")

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED libsmack dlog)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS_CCOV "--coverage")
SET(CMAKE_CXX_FLAGS_CCOV "--coverage")

SET(src_dir "./src")
SET(include_dir "./include")

## Additional flag
ADD_DEFINITIONS("-fvisibility=hidden")
ADD_DEFINITIONS("-DSHAREDIR=${SHAREDIR}")
ADD_DEFINITIONS("-DHOMEDIR=${HOMEDIR}")
ADD_DEFINITIONS("-Wall -Werror")

#ADD_DEFINITIONS("-DSMACK_ENABLED")
#ADD_DEFINITIONS("-DDLOG_DEBUG_ENABLED")    #enables dlogutil logs
ADD_DEFINITIONS("-DDLOG_ERROR_ENABLED")

###################################################################################################
## for libprivilege-control.so (library)
INCLUDE_DIRECTORIES(${pkgs_INCLUDE_DIRS})
SET(libprivilege-control_SOURCES
	${src_dir}/privilege-control.c
	${src_dir}/access-db.c
	)
SET(libprivilege-control_LDFLAGS " -module -avoid-version ")
SET(libprivilege-control_CFLAGS  " ${CFLAGS} -fPIC -I${include_dir}")
#SET(libprivilege-control_LIBADD " ")

ADD_LIBRARY(privilege-control SHARED ${libprivilege-control_SOURCES})
TARGET_LINK_LIBRARIES(privilege-control ${pkgs_LDFLAGS} ${pkgs_LIBRARIES})
SET_TARGET_PROPERTIES(privilege-control PROPERTIES COMPILE_FLAGS "${libprivilege-control_CFLAGS}")
SET_TARGET_PROPERTIES(privilege-control PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(privilege-control PROPERTIES VERSION ${VERSION})
###################################################################################################

###################################################################################################
## for slp-su (excutable)
SET(slp-su_SOURCES ${src_dir}/slp-su.c)
SET(slp-su_LDFLAGS " -module -avoid-version ")
SET(slp-su_CFLAGS  " ${CFLAGS} -fPIC -I${include_dir}")

ADD_EXECUTABLE(slp-su ${slp-su_SOURCES})
TARGET_LINK_LIBRARIES(slp-su ${pkgs_LDFLAGS} ${pkgs_LIBRARIES} privilege-control)
SET_TARGET_PROPERTIES(slp-su PROPERTIES COMPILE_FLAGS "${slp-su_CFLAGS}")
###################################################################################################

CONFIGURE_FILE(libprivilege-control.pc.in libprivilege-control.pc @ONLY)

FILE(GLOB smackfiles ${CMAKE_CURRENT_SOURCE_DIR}/permissions/*.smack)

INSTALL(TARGETS privilege-control DESTINATION  ${LIB_INSTALL_DIR} COMPONENT RuntimeLibraries)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/libprivilege-control.pc DESTINATION  ${LIB_INSTALL_DIR}/pkgconfig)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/passwd DESTINATION /opt/etc/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/group DESTINATION /opt/etc/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/smack_default_rules DESTINATION /opt/etc/smack/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/smack_application_rules DESTINATION /opt/etc/smack/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/smack_default_labeling DESTINATION /etc/rc.d/init.d/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/smack_rules DESTINATION /etc/rc.d/init.d/)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/privilege-control.h DESTINATION ${INCLUDE_INSTALL_DIR})
INSTALL(FILES ${smackfiles} DESTINATION ${SHAREDIR})
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/app_group_list DESTINATION ${SHAREDIR})
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/dev_group_list DESTINATION ${SHAREDIR})
INSTALL(FILES .privilege_control_all_apps_id.db DESTINATION /opt/dbspace)
INSTALL(FILES .privilege_control_all_avs_id.db DESTINATION /opt/dbspace)
INSTALL(FILES .privilege_control_app_gids.db DESTINATION /opt/dbspace)
#INSTALL(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/udev/ DESTINATION lib/udev)
INSTALL(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/slp-su DESTINATION bin)
