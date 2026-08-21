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


# ── Stage 2: final Kali image ───────────────────────────────────────────────
FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.title="kali-mcp-box" \
      org.opencontainers.image.description="Kali container with pentest tools for use via MCP"

# ── Tools via apt ──────────────────────────────────────────────────────────
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        # recon
        nmap \
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
        # database
        mariadb-client \
        # wordlists and support
        wordlists \
        iputils-ping \
        curl \
        wget \
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

# ── Copy Go binaries from the builder ───────────────────────────────────────
COPY --from=go-builder /root/go/bin/subfinder  /usr/local/bin/subfinder
COPY --from=go-builder /root/go/bin/katana     /usr/local/bin/katana
COPY --from=go-builder /root/go/bin/nuclei     /usr/local/bin/nuclei
COPY --from=go-builder /root/go/bin/dalfox     /usr/local/bin/dalfox
COPY --from=go-builder /root/go/bin/gowitness  /usr/local/bin/gowitness
COPY --from=go-builder /root/go/bin/httpx      /usr/local/bin/httpx

# ── Additional wordlists ─────────────────────────────────────────────────────
COPY config/sensitive-paths.txt /usr/share/wordlists/sensitive-paths.txt

# ── Nuclei templates ─────────────────────────────────────────────────────────
# Downloads templates during the build so the container is ready to go
# without needing internet on first use.
RUN nuclei -update-templates -silent || true

# ── Output directories ───────────────────────────────────────────────────────
RUN mkdir -p /tmp/sqlmap-results /tmp/gowitness /tmp/nuclei-results

# ── Healthcheck ───────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD nmap --version && nikto -Version && nuclei -version || exit 1

# Container stays idle, waiting for the MCP server to exec into it
CMD ["tail", "-f", "/dev/null"]
