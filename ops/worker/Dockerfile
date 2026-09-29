FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates \
 && rm -rf /var/lib/apt/lists
ARG TARGETARCH
RUN curl -fsSL -o /tmp/sops https://github.com/getsops/sops/releases/download/v3.10.2/sops-v3.10.2.linux.${TARGETARCH} \
 && install -m755 /tmp/sops /usr/local/bin/sops && rm /tmp/sops
RUN curl -fsSL https://opencode.ai/install | bash \
 && ln -s /root/.opencode/bin/opencode /usr/local/bin/opencode
# docker CLI for conductor (opencode infra actions + health checks)
RUN case ${TARGETARCH} in amd64) DA=x86_64;; arm64) DA=aarch64;; *) echo bad-arch; exit 1;; esac \
 && curl -fsSL -o /tmp/d.tgz https://download.docker.com/linux/static/stable/${DA}/docker-27.3.1.tgz \
 && tar -xzf /tmp/d.tgz -C /tmp && install -m755 /tmp/docker/docker /usr/local/bin/docker \
 && rm -rf /tmp/d.tgz /tmp/docker
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY qw.py watcher.py worker.py conductor.py entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
