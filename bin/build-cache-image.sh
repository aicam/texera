#!/usr/bin/env bash
# Helper to build+push one dknet image for the caching feature.
# Usage: build-cache-image.sh <dockerfile-basename> <published-image>:<tag>
set -euo pipefail
DOCKERFILE="$1"
IMAGE="$2"
cd /home/ali/IdeaProjects/texera
docker buildx build \
  --builder default \
  --platform linux/amd64 \
  --network=host \
  --build-arg JOOQ_JDBC_URL='jdbc:postgresql://localhost:5432/texera_db_hackathon' \
  --build-arg JOOQ_JDBC_USERNAME=codegen \
  --build-arg JOOQ_JDBC_PASSWORD=codegen \
  -f "bin/${DOCKERFILE}.dockerfile" \
  -t "${IMAGE}" \
  --push .
echo "BUILD_OK ${IMAGE}"
