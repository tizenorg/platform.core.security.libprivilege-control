#Copyright (c) 2012 Samsung Electronics Co., Ltd All Rights Reserved
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

# @file        CMakeLists.txt
# @author      Pawel Polawski (p.polawski@samsung.com)
# @version     0.1
# @brief
#
INCLUDE(FindPkgConfig)
SET(TARGET "rule_loader")

#dependencies
PKG_CHECK_MODULES(TARGET_DEP
    libsmack
    REQUIRED
    )

#files to compile
SET(TARGET_SOURCES
    ${PROJECT_SOURCE_DIR}/rule_loader/rule_loader.c
    ${PROJECT_SOURCE_DIR}/src/access-db.c
    ${PROJECT_SOURCE_DIR}/src/common.c
    ${PROJECT_SOURCE_DIR}/src/privilege-control.c
    )

#header directories
INCLUDE_DIRECTORIES(
    ${TARGET_DEP_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/include
    )

#preprocessor definitions
#ADD_DEFINITIONS("-DDPL_LOGS_ENABLED")

#output format
ADD_EXECUTABLE(${TARGET} ${TARGET_SOURCES})

#linker directories
TARGET_LINK_LIBRARIES(${TARGET}
    ${TARGET_DEP_LIBRARIES}
    privilege-control
    )

#place for output file
INSTALL(TARGETS ${TARGET}
    DESTINATION /usr/bin
    PERMISSIONS
    OWNER_READ
    OWNER_WRITE
    OWNER_EXECUTE
    )

#place for additional systemd service
INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/rule_loader/smack-late-rules.service
    DESTINATION /usr/lib/systemd/system
    PERMISSIONS
    OWNER_READ
    OWNER_WRITE
    OWNER_EXECUTE
    )

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/rule_loader/smack-early-rules.service
    DESTINATION /usr/lib/systemd/system
    PERMISSIONS
    OWNER_READ
    OWNER_WRITE
    OWNER_EXECUTE
    )
