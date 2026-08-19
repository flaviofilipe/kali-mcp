# ── Stage 1: Go tools builder ─────────────────────────────────────────────────
# Compila todas as ferramentas Go em uma camada separada para manter a imagem
# final enxuta — só os binários são copiados para o stage final.
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


# ── Stage 2: imagem final Kali ────────────────────────────────────────────────
FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.title="kali-mcp-box" \
      org.opencontainers.image.description="Container Kali com ferramentas de pentest para uso via MCP"

# ── Ferramentas via apt ───────────────────────────────────────────────────────
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        # reconhecimento
        nmap \
        # análise web
        nikto \
        testssl.sh \
        wpscan \
        # exploração
        sqlmap \
        hydra \
        gobuster \
        dirb \
        ffuf \
        # banco de dados
        mariadb-client \
        # wordlists e suporte
        wordlists \
        iputils-ping \
        curl \
        wget \
        ca-certificates \
        chromium \
    && \
    # descompactar rockyou.txt
    gunzip -f /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true && \
    # limpar cache do apt
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    # o pacote instala como 'testssl'; o MCP chama 'testssl.sh'
    ln -sf /usr/bin/testssl /usr/bin/testssl.sh && \
    # wordlist de usuários unix para hydra (metasploit não está instalado)
    printf 'root\nadmin\nuser\ntest\nguest\nubuntu\nkali\nwww-data\nftp\npostgres\nmysql\noperator\nservice\nbackup\ndaemon\n' \
        > /usr/share/wordlists/unix_users.txt

# ── Copiar binários Go do builder ─────────────────────────────────────────────
COPY --from=go-builder /root/go/bin/subfinder  /usr/local/bin/subfinder
COPY --from=go-builder /root/go/bin/katana     /usr/local/bin/katana
COPY --from=go-builder /root/go/bin/nuclei     /usr/local/bin/nuclei
COPY --from=go-builder /root/go/bin/dalfox     /usr/local/bin/dalfox
COPY --from=go-builder /root/go/bin/gowitness  /usr/local/bin/gowitness
COPY --from=go-builder /root/go/bin/httpx      /usr/local/bin/httpx

# ── Wordlists adicionais ──────────────────────────────────────────────────────
COPY config/sensitive-paths.txt /usr/share/wordlists/sensitive-paths.txt

# ── Templates do Nuclei ───────────────────────────────────────────────────────
# Baixa os templates durante o build para que o container já esteja pronto
# sem precisar de internet no primeiro uso.
RUN nuclei -update-templates -silent || true

# ── Diretórios de output ──────────────────────────────────────────────────────
RUN mkdir -p /tmp/sqlmap-results /tmp/gowitness /tmp/nuclei-results

# ── Healthcheck ───────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD nmap --version && nikto -Version && nuclei -version || exit 1

# Container fica em modo idle aguardando exec do MCP server
CMD ["tail", "-f", "/dev/null"]
