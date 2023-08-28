fn main() {
    ::capnpc::CompilerCommand::new()
        .output_path("src/")
        .file("proto/vldpipe.capnp")
        .run()
        .expect("compiling schema");
}
