use std::collections::HashMap;

use risc0_build::{embed_methods_with_options, DockerOptions, GuestOptions};

fn main() {
    // Builds can be made deterministic, and thereby reproducible, by using Docker to build the
    // guest. Check the RISC0_USE_DOCKER variable and use Docker to build the guest if set.
    println!("cargo:rerun-if-env-changed=RISC0_USE_DOCKER");
    let docker_opts = DockerOptions {
        root_dir: Some("../".into()), // this can also point to the path where the docker context should be
    };
    let guest_opts = GuestOptions {
        use_docker: Some(docker_opts),
        ..Default::default()
    };
    // Generate Rust source files for the methods crate.
    embed_methods_with_options(HashMap::from([("address", guest_opts)]));
}
