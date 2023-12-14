add_library(abe STATIC
  base64.cc
  abe_crypto.cc
  rewrite.cc
)
target_include_directories(abe PUBLIC /usr/local/lib /usr/lib/x86_64-linux-gnu)
target_link_libraries(abe PUBLIC mysqlclient crypto relic relic_ec openabe)