# 开发环境镜像：本项目四个并列实现（Go / Python / Node.js / PHP）的运行与测试环境
# 见 README「四个并列的实现」与 .codebuddy/rules/project.md。
# 本文件只服务本仓自身需要的能力，不承载任何调用方项目的上下文（ADR-0005）。
FROM golang:1.22-bookworm

ARG NODE_MAJOR=20

ENV DEBIAN_FRONTEND=noninteractive \
    GOPROXY=https://goproxy.cn,direct \
    PIP_INDEX_URL=https://mirrors.tencent.com/pypi/simple \
    NPM_CONFIG_REGISTRY=https://registry.npmmirror.com \
    # 禁止 CodeBuddy CLI 在容器内拉起后台任务进程
    CODEBUDDY_CODE_DISABLE_BACKGROUND_TASKS=1

# 基础工具 + Python 环境 + OpenCV/ffmpeg 运行时依赖。
# libgl1 / libglib2.0-0 是 opencv-python 的运行时依赖，缺了 python-client/play.py 的
# `import cv2` 直接 ImportError（ffmpeg 另用于「喂解码器」验证，见 testing.md）。
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl wget vim jq ca-certificates openssh-client gnupg \
        git-lfs \
        python3 python3-pip python3-venv python3-dev \
        build-essential pkg-config \
        libgl1 libglib2.0-0 ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Git LFS 必须 install 一次，samples/ 里的真机样本（*.ps）才拉得下来。
# 不拉即回放用例 skip ——「skip 等于没跑回归」（testing.md 第三条）。
RUN git lfs install --system

# Node.js：nodejs-client 用 `node --test`，package.json 要求 >=18。
# 走 NodeSource 的 nodistro 套件（amd64/arm64 均可）；deb.nodesource.com 在本环境可达，
# 故不再叠加第三方镜像源。
RUN set -eux; \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg; \
    chmod 644 /usr/share/keyrings/nodesource.gpg; \
    echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends nodejs; \
    rm -rf /var/lib/apt/lists/*; \
    node --version; \
    npm --version

# 预热 Node 依赖（npm ci 走 lockfile，锁定 ws 8.21.0 —— CVE 修复版本）。
# 真源是 nodejs-client/package-lock.json；改版本时记得同步 .cnb.yml 的 ifModify。
COPY nodejs-client/package.json nodejs-client/package-lock.json /tmp/nodejs-client/
RUN cd /tmp/nodejs-client && npm ci --no-audit --no-fund && rm -rf /tmp/nodejs-client

# 安装 VSCode Server
RUN set -ex && \
    CS_ARCH="amd64"; [ "$TARGETARCH" = "arm64" ] && CS_ARCH="arm64"; \
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


# 安装 PHP 8.4（bookworm 自带 8.2，php-client 要求 8.4+，走 Sury 源）
RUN set -ex && \
    apt-get update && \
    apt-get install -y --no-install-recommends lsb-release ca-certificates apt-transport-https gnupg && \
    curl -fsSL https://packages.sury.org/php/apt.gpg -o /usr/share/keyrings/sury-php.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/sury-php.gpg] https://packages.sury.org/php/ bookworm main" \
        > /etc/apt/sources.list.d/sury-php.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends php8.4-cli php8.4-mbstring php8.4-curl php8.4-xml php8.4-gmp && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["bash"]
