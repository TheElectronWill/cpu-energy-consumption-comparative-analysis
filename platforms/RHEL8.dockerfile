FROM registry.access.redhat.com/ubi8/ubi:8.7

RUN mkdir -p /root/target
ENV CARGO_TARGET_DIR="/root/target"

# a C linker is required for some dependencies of the project
RUN dnf install -y gcc

# WARNING: it's not good to do
#   RUN dnf install -y rust-toolset
# because that version of Rust is too old to build the project.
# Therefore, we install Rustup manually.
RUN mkdir -m777 /opt/rust /opt/cargo
ENV RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal

# Building eBPF programs requires bpf-linker
# NOTE: for an architecture other than x86_64, llvm is required too
# see https://aya-rs.dev/book/start/development/#prerequisites
RUN if [ $(arch) = "x86_64" ]; then \
        cargo install bpf-linker; \
    else \
        #dnf install -y llvm-toolset llvm-toolset-dev; \
        #cargo install --no-default-features --features system-llvm bpf-linker; \
        echo BADBADBAD; \
    fi

ENTRYPOINT ["/bin/bash"]
