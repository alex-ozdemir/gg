protobuf_generate_cpp(protobufs_libs protobufs_hdrs gg.proto thunk.proto meow.proto)
add_library(protobufs ${protobufs_libs})
target_link_libraries(protobufs PUBLIC ${Protobuf_LIBRARIES})
target_include_directories(protobufs PUBLIC ${Protobuf_INCLUDE_DIRS})
