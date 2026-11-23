FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends g++ make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile ./
COPY include/ include/
COPY src/ src/
RUN make -j2 all

FROM ubuntu:24.04
LABEL org.opencontainers.image.source="https://github.com/sammy-9930/PacketLens"
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/cpp-sniffer /usr/local/bin/cpp-sniffer
USER 65534:65534
ENTRYPOINT ["cpp-sniffer"]
CMD ["--help"]
