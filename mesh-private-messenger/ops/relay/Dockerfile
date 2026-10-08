# morse-relay: POST /v1/fork-evidence on port 8787. The wallet is a mounted
# solana-keygen file; nothing else is stored.
#   docker build -t morse-relay ops/relay
#   docker run -p 8787:8787 -v /secure/relay-wallet.json:/run/secrets/wallet.json:ro \
#     -e MORSE_RELAY_WALLET=/run/secrets/wallet.json -e MORSE_RELAY_RPC=https://… \
#     -e MORSE_JUDGE_PROGRAM_ID=… -e MORSE_RELAY_LOGS=morse-main=https://… morse-relay
FROM node:22-alpine
WORKDIR /relay
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY cli.mjs frk.mjs judge.mjs relay.mjs ./
USER node
ENV NODE_ENV=production PORT=8787
EXPOSE 8787
ENTRYPOINT ["node", "cli.mjs"]
CMD ["serve"]
