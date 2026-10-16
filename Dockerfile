# agentaudit in one image.
#
# The CodeQL CLI is the biggest barrier to running a full scan (a ~400 MB download, and it has
# to be unpacked where the frontend can find it), so it is baked in here.
#
#   docker build -t agentaudit .
#   docker run --rm agentaudit                                            # bundled sample
#   docker run --rm -v "$PWD/myproject:/scan/myproject:ro" agentaudit \
#       --path /scan/myproject --tag myproj --out /scan/out
#
# To triage with an LLM, mount a key file and pass the environment variables:
#
#   docker run --rm -v "$HOME/.deepseek_key:/keys/deepseek:ro" \
#       -e DEEPSEEK_KEY_FILE=/keys/deepseek -e AF_LLM_MAX_CNY=3 \
#       agentaudit --demo --llm
#
# Other commands need their own entry point:
#
#   docker run --rm --entrypoint agentaudit agentaudit log
#   docker run --rm --entrypoint agentaudit agentaudit validate
#   docker run --rm --entrypoint /opt/agentaudit/_tools/codeql/codeql agentaudit version
#
# VERIFYING THIS FILE
# -------------------
# `docker build` was not run on the machine where this was written, so treat the first build as
# the test. It is written to fail loudly rather than quietly: the CLI is executed during the
# build (step 2 below), and CI smoke-tests the image on every push (.github/workflows/ci.yml,
# the `docker` job). If the release layout ever changes, the build stops at that step instead
# of producing an image whose scanner silently cannot run.

FROM python:3.11-slim

# Pin the CLI. Bump with --build-arg CODEQL_VERSION=vX.Y.Z; the Python query pack shipped with
# the CLI has to match the CLI version.
ARG CODEQL_VERSION=v2.27.2
ARG CODEQL_ZIP=codeql-linux64.zip

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git unzip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/agentaudit

# 1) Unpack the CLI to ./_tools, which is where the frontend looks by default.
RUN mkdir -p _tools \
 && curl -fsSL --retry 3 --retry-delay 5 -o /tmp/codeql.zip \
      "https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_VERSION}/${CODEQL_ZIP}" \
 && unzip -q /tmp/codeql.zip -d _tools \
 && rm -f /tmp/codeql.zip

# 2) Fail the build here if the archive did not unpack where the frontend expects it.
RUN test -x _tools/codeql/codeql \
      || { echo "ERROR: the CodeQL archive did not unpack to _tools/codeql/codeql"; \
           echo "contents of _tools:"; ls -la _tools; exit 1; } \
 && _tools/codeql/codeql version

# 3) Python dependency, then the package itself so the `agentaudit` command exists in here.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir --no-deps -e . && agentaudit --version

ENV AF_CODEQL=/opt/agentaudit/_tools/codeql/codeql \
    PYTHONUNBUFFERED=1

# Output goes to ./out under this directory; mount a volume to see it on the host.
WORKDIR /scan

ENTRYPOINT ["agentaudit", "scan"]
CMD ["--demo"]
