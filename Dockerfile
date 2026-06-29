# ozzy-api — Express API + native Agatha file & URL engines (koffi FFI)
#
# Debian (glibc) base is required: the native engine .so files and ONNX Runtime
# link against glibc/libstdc++/libgomp and will NOT run on Alpine/musl.
#
# The engine packages under engine/package and url-engine/package must contain
# the Linux .so builds (libagatha.so / libhyperlinkengine.so) plus a
# Linux libonnxruntime.so next to each. The Windows .dll files may also be
# present — the binding picks the right one per platform, so they're harmless.
FROM node:20-bookworm-slim

# Runtime libs the native engines + ONNX Runtime need.
RUN apt-get update \
  && apt-get install -y --no-install-recommends libgomp1 libstdc++6 ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first for better layer caching. koffi ships prebuilt
# Linux binaries, so no native toolchain is needed here.
COPY package*.json ./
RUN npm ci --omit=dev

# App source + engine packages (incl. the .so binaries staged into them).
COPY . .

ENV NODE_ENV=production \
    PORT=5000
EXPOSE 5000

CMD ["node", "index.js"]
