ARG MORSE_SERVICES_IMAGE
FROM ${MORSE_SERVICES_IMAGE}
ARG SOURCE_DATE_EPOCH
ARG MORSE_REVISION
ARG MESH_LANG_REVISION
LABEL org.opencontainers.image.title="Morse pull witness" \
      org.opencontainers.image.revision="${MORSE_REVISION}" \
      org.morse.mesh-revision="${MESH_LANG_REVISION}"
ENV MESSENGER_WITNESS_MODE=pull \
    MESSENGER_WITNESS_CHECKPOINT_PATH=/state/checkpoint
USER 65532:65532
ENTRYPOINT ["/app/transparency-witness"]
CMD []
