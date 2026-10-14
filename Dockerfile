# agentaudit in one image.
#
# The CodeQL CLI is the biggest barrier to running a full scan (a ~500 MB download, and it
# has to be unpacked where the frontend can find it), so it is baked in here.
#
#   docker build -t agentaudit .
#   docker run --rm -v "$PWD/myproject:/scan/myproject:ro" agentaudit \
#       --path /scan/myproject --tag myproj --out /scan/out
#
# Or just see it work on the bundled sample:
#
#   docker run --rm agentaudit
#
# To triage with an LLM, mount a key file and pass the environment variables:
#
#   docker run --rm -v "$HOME/.deepseek_key:/keys/deepseek:ro" \
#       -e DEEPSEEK_KEY_FILE=/keys/deepseek -e AF_LLM_MAX_CNY=3 \
#       agentaudit --demo --llm

FROM python:3.11-slim

# Pin the CLI; bump with --build-arg CODEQL_VERSION=vX.Y.Z.
# The Python query pack shipped with the CLI must match this version.
ARG CODEQL_VERSION=v2.27.2
ARG CODEQL_ZIP=codeql-linux64.zip

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git unzip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/agentaudit

# Unpack the CLI to ./_tools/codeql, which is where the frontend looks by default.
RUN mkdir -p _tools \
 && curl -fsSL -o /tmp/codeql.zip \
      "https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_VERSION}/${CODEQL_ZIP}" \
 && unzip -q /tmp/codeql.zip -d _tools \
 && rm -f /tmp/codeql.zip \
 && _tools/codeql/codeql version

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV AF_CODEQL=/opt/agentaudit/_tools/codeql/codeql \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "app/scan.py"]
CMD ["--demo"]
