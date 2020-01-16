protobuf_generate_cpp(protobufs_libs protobufs_hdrs gg.proto thunk.proto meow.proto)
add_library(protobufs ${protobufs_libs})
target_link_libraries(protobufs ${Protobuf_LIBRARIES})
