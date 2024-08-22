FROM docker.io/paritytech/ci-unified:latest as builder

WORKDIR /orehub
COPY . /orehub

RUN cargo fetch
RUN cargo build --locked --release

FROM docker.io/parity/base-bin:latest

COPY --from=builder /orehub/target/release/orehub-node /usr/local/bin

USER root
RUN useradd -m -u 1001 -U -s /bin/sh -d /orehub orehub && \
    mkdir -p /data /orehub/.local/share && \
    chown -R orehub:orehub /data && \
    ln -s /data /orehub/.local/share/orehub && \
    # unclutter and minimize the attack surface
    rm -rf /usr/bin /usr/sbin && \
    # check if executable works in this container
    /usr/local/bin/orehub-node --version

USER orehub

EXPOSE 30333 9933 9944 9615
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/orehub-node"]
