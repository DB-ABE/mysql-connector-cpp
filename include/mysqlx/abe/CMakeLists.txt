SET(headers base64.h abe_crypto.h rewrite.h)

check_headers(${headers})

ADD_HEADERS(${headers})
ADD_HEADER_CHECKS()
INSTALL(FILES ${headers} DESTINATION ${INSTALL_INCLUDE_DIR}/mysqlx/abe COMPONENT XDevAPIDev)
