# 开发环境镜像：Python 3 + Go，用于海康 WebSocket 客户端项目
FROM golang:1.22-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    GOPROXY=https://goproxy.cn,direct \
    PIP_INDEX_URL=https://mirrors.tencent.com/pypi/simple

# 基础工具 + Python 环境 + OpenCV/ffmpeg 运行时依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl wget vim jq ca-certificates openssh-client \
        python3 python3-pip python3-venv python3-dev \
        build-essential pkg-config \
        libgl1 libglib2.0-0 ffmpeg \
    && rm -rf /var/lib/apt/lists/*

RUN set -ex && \
    git lfs install && \
    CS_ARCH="amd64"; [ "$TARGETARCH" = "arm64" ] && CS_ARCH="arm64"; \
    # 安装 VSCode Server
    curl -fsSL https://code-server.dev/install.sh | sh -s -- --version 4.99.4 && \
    # 常用 VSCode 扩展（安装失败不阻断构建，某些扩展在 Open VSX 上不存在）
    code-server --install-extension cnbcool.cnb-welcome || true && \
    code-server --install-extension tencent-cloud.coding-copilot || true && \
    code-server --install-extension esbenp.prettier-vscode || true && \
    code-server --install-extension golang.go || true && \
    code-server --install-extension dbaeumer.vscode-eslint || true && \
    code-server --install-extension redhat.vscode-yaml || true && \
    code-server --install-extension cloudstudio.live-server || true && \
    code-server --install-extension ms-python.python || true && \
    code-server --install-extension ms-azuretools.vscode-docker || true && \
    code-server --install-extension bmewburn.vscode-intelephense-client || true && \
    code-server --install-extension PKief.material-icon-theme || true && \
    code-server --install-extension Vue.volar || true && \
    code-server --install-extension usernamehw.errorlens || true && \
    code-server --install-extension ms-vscode.cpptools || true && \
    code-server --install-extension ms-vscode.cmake-tools || true && \
    # 清理 code-server 安装残留
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/*


# 安装项目 Python 依赖（bookworm 的 pip 需要 --break-system-packages 装入系统环境）
COPY python-client/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt \
    && rm -f /tmp/requirements.txt

# 预热 Go 模块缓存
COPY go-client/go.mod go-client/go.sum /tmp/go-client/
RUN cd /tmp/go-client && go mod download && rm -rf /tmp/go-client

WORKDIR /workspace

CMD ["bash"]
