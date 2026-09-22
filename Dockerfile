# OVERLORD in a container — the fuse backend (fuse-overlayfs), which needs
# /dev/fuse and CAP_SYS_ADMIN from the host. The kernel backend (userns
# overlay + jail) is not available inside a container.
#
#   docker build -t overlord .
#   docker volume create overlord-data
#   docker run --rm -it -v overlord-data:/data overlord users add admin --role admin
#   docker run --rm -it -v overlord-data:/data overlord tls selfsign --host overlord.example.lan
#   docker run -d --name overlord -p 7777:7777 -v overlord-data:/data -v /srv/code:/work \
#       --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined overlord
#
# The default command serves the workspace on 0.0.0.0:7777 over TLS with the
# certificate under /data/tls, which is why accounts and the certificate must
# exist first: the server refuses to bind beyond loopback without them.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends fuse-overlayfs git openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --create-home --home-dir /home/overlord overlord

COPY overlord.py agent.py providers.py review.py mcp.py memory.py auth.py cost.py audit.py netproxy.py policycheck.py \
     retention.py skills.py oidc.py notify.py vault.py bundle.py ui.py chatui.py /usr/local/lib/overlord/
COPY sdk/overlord_client.py /usr/local/lib/overlord/overlord_client.py
COPY packaging/ebpf/provenance.bt /usr/local/lib/overlord/provenance.bt
RUN printf '#!/bin/sh\nexec python3 /usr/local/lib/overlord/overlord.py "$@"\n' > /usr/local/bin/overlord \
 && chmod 0755 /usr/local/bin/overlord \
 && mkdir -p /data /work && chown overlord:overlord /data /work

ENV OVERLORD_HOME=/data
USER overlord
WORKDIR /work
VOLUME ["/data"]
EXPOSE 7777
HEALTHCHECK --interval=30s --timeout=5s CMD python3 -c "import ssl,urllib.request;c=ssl.create_default_context();c.check_hostname=False;c.verify_mode=ssl.CERT_NONE;urllib.request.urlopen('https://127.0.0.1:7777/healthz',context=c,timeout=4)" || exit 1

ENTRYPOINT ["overlord"]
CMD ["ui", "--bind", "0.0.0.0", "--port", "7777", "--tls-cert", "/data/tls/cert.pem", "--tls-key", "/data/tls/key.pem", "--log-json"]
