fn main() {
    println!("cargo:rerun-if-changed=proto/v1/attestation.proto");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/v1/attestation.proto"], &["proto"])
        .expect("failed to compile protobuf definitions");
}
