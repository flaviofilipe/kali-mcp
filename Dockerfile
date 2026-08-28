# ── Stage 1: Go tools builder ─────────────────────────────────────────────────
# Compiles all Go tools in a separate layer to keep the final image lean —
# only the binaries get copied into the final stage.
FROM golang:1.24-bookworm AS go-builder

ENV GOPATH=/root/go \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    GOTOOLCHAIN=auto

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/hahwul/dalfox/v2@latest
RUN go install -v github.com/sensepost/gowitness@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# Pivoting
RUN go install -v github.com/jpillora/chisel@latest

# ligolo-ng: no `go install`-able module path (its cmd/ packages aren't a
# public importable module), so grab the pinned prebuilt Linux release
# instead. Pin a specific tag for reproducible builds — never "latest".
ARG LIGOLO_VERSION=v0.9.1
RUN mkdir -p /root/go/bin && \
    curl -fsSL -o /tmp/ligolo-proxy.tar.gz \
        "https://github.com/nicocha30/ligolo-ng/releases/download/${LIGOLO_VERSION}/ligolo-ng_proxy_${LIGOLO_VERSION#v}_linux_amd64.tar.gz" && \
    curl -fsSL -o /tmp/ligolo-agent.tar.gz \
        "https://github.com/nicocha30/ligolo-ng/releases/download/${LIGOLO_VERSION}/ligolo-ng_agent_${LIGOLO_VERSION#v}_linux_amd64.tar.gz" && \
    tar -xzf /tmp/ligolo-proxy.tar.gz -C /root/go/bin proxy && mv /root/go/bin/proxy /root/go/bin/ligolo-ng-proxy && \
    tar -xzf /tmp/ligolo-agent.tar.gz -C /root/go/bin agent && mv /root/go/bin/agent /root/go/bin/ligolo-ng-agent && \
    rm -f /tmp/ligolo-proxy.tar.gz /tmp/ligolo-agent.tar.gz

# trufflehog: `go install .../v3@latest` fails — its go.mod carries replace
# directives, which `go install` refuses for a non-main module target.
# Grab the pinned prebuilt Linux release instead, same as ligolo-ng above.
ARG TRUFFLEHOG_VERSION=3.97.1
RUN curl -fsSL -o /tmp/trufflehog.tar.gz \
        "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" && \
    tar -xzf /tmp/trufflehog.tar.gz -C /root/go/bin trufflehog && \
    rm -f /tmp/trufflehog.tar.gz


# ── Stage 2: static binaries (no compilation needed) ────────────────────────
# LinPEAS / WinPEAS, pinned to a specific PEASS-ng release tag for
# reproducible builds. Mimikatz is staged separately, conditionally, below.
FROM debian:bookworm-slim AS static-bin-fetcher

ARG PEASS_VERSION=20260824-c1d29dcd
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates curl && \
    mkdir -p /payloads && \
    curl -fsSL -o /payloads/linpeas.sh \
        "https://github.com/peass-ng/PEASS-ng/releases/download/${PEASS_VERSION}/linpeas.sh" && \
    curl -fsSL -o /payloads/winPEASx64.exe \
        "https://github.com/peass-ng/PEASS-ng/releases/download/${PEASS_VERSION}/winPEASx64.exe" && \
    chmod +r /payloads/*


# ── Stage 3: final Kali image ───────────────────────────────────────────────
FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.title="kali-mcp-box" \
      org.opencontainers.image.description="Kali container with pentest tools for use via MCP"

# Set to "true" to stage Mimikatz into the image (see the mimikatz-fetcher
# stage below). Off by default: Mimikatz is frequently AV/registry-policy
# flagged, so it's opt-in — see SECURITY.md.
ARG INCLUDE_OFFENSIVE_BINARIES=false

# ── Tools via apt ──────────────────────────────────────────────────────────
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        # recon
        nmap \
        smbclient \
        # web analysis
        nikto \
        testssl.sh \
        wpscan \
        # exploitation
        sqlmap \
        hydra \
        gobuster \
        dirb \
        ffuf \
        metasploit-framework \
        # credentials
        john \
        hashcat \
        hashid \
        exploitdb \
        # network pivoting
        proxychains4 \
        # forensics / binary analysis
        radare2 \
        gdb \
        binwalk \
        exiftool \
        steghide \
        # database
        mariadb-client \
        # session management (tmux keeps a reverse shell / evil-winrm session
        # alive inside the container across separate `docker exec` calls)
        tmux \
        netcat-traditional \
        # evil-winrm is a Ruby gem — see the gem install step below
        ruby \
        ruby-dev \
        build-essential \
        # netexec's `aardwolf` dependency has no prebuilt wheel for this
        # platform and needs to compile from source
        rustc \
        cargo \
        # wordlists and support
        wordlists \
        iputils-ping \
        curl \
        wget \
        git \
        ca-certificates \
        chromium \
    && \
    # decompress rockyou.txt
    gunzip -f /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true && \
    # clean apt cache
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    # the package installs as 'testssl'; the MCP calls 'testssl.sh'
    ln -sf /usr/bin/testssl /usr/bin/testssl.sh && \
    # unix username wordlist for hydra (metasploit is not installed)
    printf 'root\nadmin\nuser\ntest\nguest\nubuntu\nkali\nwww-data\nftp\npostgres\nmysql\noperator\nservice\nbackup\ndaemon\n' \
        > /usr/share/wordlists/unix_users.txt

# evil-winrm: Ruby gem, not in the apt repo
RUN gem install evil-winrm --no-document

# Responder: not reliably in the Kali apt repo across releases — clone
# directly and expose it on PATH as a thin wrapper.
RUN git clone --depth 1 https://github.com/lgandx/Responder.git /opt/Responder && \
    printf '#!/bin/sh\nexec python3 /opt/Responder/Responder.py "$@"\n' > /usr/local/bin/responder && \
    chmod +x /usr/local/bin/responder

# ── Copy Go/static binaries from the builder stages ─────────────────────────
COPY --from=go-builder /root/go/bin/subfinder        /usr/local/bin/subfinder
COPY --from=go-builder /root/go/bin/katana           /usr/local/bin/katana
COPY --from=go-builder /root/go/bin/nuclei           /usr/local/bin/nuclei
COPY --from=go-builder /root/go/bin/dalfox           /usr/local/bin/dalfox
COPY --from=go-builder /root/go/bin/gowitness        /usr/local/bin/gowitness
# Renamed on purpose: the Python `httpx` HTTP-client library (a transitive
# dependency of netexec's certipy-ad, pulled into /opt/pymcp-venv below)
# ships its own `httpx` console script, and /opt/pymcp-venv/bin is ahead of
# /usr/local/bin on PATH (needed so plain `python3` resolves to the venv,
# giving angr/pwntools to any script run that way) — it would silently
# shadow ProjectDiscovery's httpx otherwise. Found by actually exec-ing into
# the built image and checking `which httpx`.
COPY --from=go-builder /root/go/bin/httpx            /usr/local/bin/httpx-projectdiscovery
COPY --from=go-builder /root/go/bin/chisel           /usr/local/bin/chisel
COPY --from=go-builder /root/go/bin/trufflehog       /usr/local/bin/trufflehog
COPY --from=go-builder /root/go/bin/ligolo-ng-proxy  /usr/local/bin/ligolo-ng-proxy
COPY --from=go-builder /root/go/bin/ligolo-ng-agent  /usr/local/bin/ligolo-ng-agent

# ── Post-exploitation payloads (LinPEAS/WinPEAS, always; Mimikatz, opt-in) ──
RUN mkdir -p /opt/mcp-payloads
COPY --from=static-bin-fetcher /payloads/linpeas.sh     /opt/mcp-payloads/linpeas.sh
COPY --from=static-bin-fetcher /payloads/winPEASx64.exe /opt/mcp-payloads/winPEASx64.exe
RUN chmod +r /opt/mcp-payloads/*

# Mimikatz — only staged when explicitly requested at build time:
#   docker compose build --build-arg INCLUDE_OFFENSIVE_BINARIES=true
# run_mimikatz() checks for this file and refuses to run if it's absent.
# Pinned to a specific mimikatz release tag for reproducible builds.
ARG MIMIKATZ_VERSION=2.2.0-20220919
RUN if [ "$INCLUDE_OFFENSIVE_BINARIES" = "true" ]; then \
        curl -fsSL -o /tmp/mimikatz.zip \
            "https://github.com/gentilkiwi/mimikatz/releases/download/${MIMIKATZ_VERSION}/mimikatz_trunk.zip" && \
        apt-get update -qq && apt-get install -y -qq --no-install-recommends unzip && \
        unzip -j /tmp/mimikatz.zip "x64/mimikatz.exe" -d /opt/mcp-payloads/ && \
        rm -f /tmp/mimikatz.zip && \
        apt-get purge -y -qq unzip && apt-get clean && rm -rf /var/lib/apt/lists/*; \
    fi

# ── Python tools (uv-managed venv, isolated from Kali's system Python) ─────
# Installed via `uv` (much faster than pip) into a dedicated venv whose
# bin/ is put on PATH — so `python3` here resolves to this venv (giving
# angr/pwntools to any script run as `python3 script.py`) and each tool's
# console-script entry point (nxc, vol, bloodhound-python, ...) is directly
# callable, no venv activation needed.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
ENV PATH="/opt/pymcp-venv/bin:${PATH}"
RUN uv venv /opt/pymcp-venv --python 3.12

# Packages actually published on PyPI under these names.
RUN uv pip install --python /opt/pymcp-venv/bin/python \
        impacket \
        bloodhound \
        volatility3 \
        angr \
        pwntools \
        requests \
        jsbeautifier \
        pycryptodomex \
        termcolor \
        cprint

# netexec and enum4linux-ng are NOT on PyPI under their tool names — install
# straight from a pinned tag instead. (netexec's pyproject.toml registers
# both `netexec` and `nxc` console scripts; enum4linux-ng's setup.py
# installs a plain `enum4linux-ng` script.)
ARG NETEXEC_VERSION=v1.5.1
ARG ENUM4LINUX_NG_VERSION=v1.3.10
RUN uv pip install --python /opt/pymcp-venv/bin/python \
        "netexec @ git+https://github.com/Pennyw0rth/NetExec.git@${NETEXEC_VERSION}" \
        "enum4linux-ng @ git+https://github.com/cddmp/enum4linux-ng.git@${ENUM4LINUX_NG_VERSION}"

# Script-only tools with no usable PyPI package — git clone at a pinned tag
# and invoke via an absolute path / thin wrapper.
# No tags in this repo — pin an exact commit SHA instead (fetched shallowly;
# GitHub supports shallow-fetching an arbitrary commit for public repos).
ARG SECRETFINDER_COMMIT=d06119dedd9c1505137d1ec4792d5d5b65c7425d
RUN git init -q /opt/secretfinder && \
    git -C /opt/secretfinder fetch --depth 1 https://github.com/m4ll0k/SecretFinder.git "${SECRETFINDER_COMMIT}" && \
    git -C /opt/secretfinder checkout -q FETCH_HEAD && \
    uv pip install --python /opt/pymcp-venv/bin/python -r /opt/secretfinder/requirements.txt

ARG JWT_TOOL_VERSION=2.2.7
RUN git clone --depth 1 --branch "v${JWT_TOOL_VERSION}" https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool && \
    uv pip install --python /opt/pymcp-venv/bin/python -r /opt/jwt_tool/requirements.txt && \
    chmod +x /opt/jwt_tool/jwt_tool.py

# graphw00f (GraphQL engine fingerprinting) — IMPORTANT: "graphw00f" IS
# registered on PyPI, but as an inert dependency-confusion decoy placeholder
# (its own long_description says so explicitly) — never `pip install
# graphw00f`. The real tool only exists as a GitHub repo; clone and wrap it.
# No requirements.txt in this repo — its only third-party dependency is
# `requests`, already installed above.
ARG GRAPHW00F_VERSION=1.2.1
RUN git clone --depth 1 --branch "${GRAPHW00F_VERSION}" https://github.com/dolevf/graphw00f.git /opt/graphw00f && \
    printf '#!/bin/sh\nexec python3 /opt/graphw00f/main.py "$@"\n' > /usr/local/bin/graphw00f && \
    chmod +x /usr/local/bin/graphw00f

# ── proxychains4 config ──────────────────────────────────────────────────────
# Default apt config points at a local Tor SOCKS4 proxy on :9050. Point it
# instead at :1080, where pivot_scan_via_proxychains() expects a chisel
# reverse-SOCKS listener or a ligolo-ng tun interface to be listening.
RUN sed -i \
        -e 's/^socks4.*$/socks5  127.0.0.1 1080/' \
        /etc/proxychains4.conf

# ── Additional wordlists ─────────────────────────────────────────────────────
COPY config/sensitive-paths.txt /usr/share/wordlists/sensitive-paths.txt

# ── Nuclei templates ─────────────────────────────────────────────────────────
# Downloads templates during the build so the container is ready to go
# without needing internet on first use.
RUN nuclei -update-templates -silent || true

# ── searchsploit database ────────────────────────────────────────────────────
# NOT `searchsploit -u`: that also pulls in the exploitdb-papers package
# (~2.5GB of unrelated whitepaper PDFs search_exploit() never reads) even
# when the actual exploit database (what search_exploit() queries) is
# already current from the exploitdb apt package installed above.

# ── Output directories ───────────────────────────────────────────────────────
RUN mkdir -p /tmp/sqlmap-results /tmp/gowitness /tmp/nuclei-results

# ── Healthcheck ───────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD nmap --version && nikto -Version && nuclei -version || exit 1

# Container stays idle, waiting for the MCP server to exec into it
CMD ["tail", "-f", "/dev/null"]
