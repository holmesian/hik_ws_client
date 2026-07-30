#!/usr/bin/env bash
# 构建开发环境镜像并推送到 CNB 制品库
set -euo pipefail

# 校验必需的环境变量
: "${CNB_DOCKER_REGISTRY:?请设置 CNB_DOCKER_REGISTRY 环境变量，如 docker.cnb.cool}"
: "${CNB_REPO_SLUG_LOWERCASE:?请设置 CNB_REPO_SLUG_LOWERCASE 环境变量，如 org/repo}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"

IMAGE="${CNB_DOCKER_REGISTRY}/${CNB_REPO_SLUG_LOWERCASE}"
TAG="${1:-latest}"

echo ">>> 构建镜像: ${IMAGE}:${TAG}"
docker build \
    -f "${SCRIPT_DIR}/Dockerfile" \
    -t "${IMAGE}:${TAG}" \
    "${REPO_ROOT}"

echo ">>> 推送镜像: ${IMAGE}:${TAG}"
docker push "${IMAGE}:${TAG}"

echo ">>> 完成: ${IMAGE}:${TAG}"
