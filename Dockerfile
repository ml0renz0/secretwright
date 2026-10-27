# The digest is pinned from the Sigstore timestamp-authority and CloudNativePG
# upstream Dockerfiles; see docs/features/F13-packaging-release.md.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

ARG TARGETARCH
ARG VERSION
LABEL org.opencontainers.image.title="secretwright" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/ml0renz0/secretwright"

COPY --chmod=0755 .container/linux_${TARGETARCH}/secretwright /usr/local/bin/secretwright
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/secretwright"]
CMD ["help"]
