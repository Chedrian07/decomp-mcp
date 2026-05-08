FROM eclipse-temurin:21-jdk-noble AS jdk

FROM python:3.12-bookworm

ARG GHIDRA_VERSION=12.0.4
ARG GHIDRA_DATE=20260303
ARG GHIDRA_ZIP_SHA256=c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120
ARG JADX_VERSION=1.5.4
ARG JADX_ZIP_SHA256=f6f0d51a4af63e430045aa64c4f110b89b53e82eb596ccb3a4bd3f865adec70e

COPY --from=jdk /opt/java/openjdk /opt/java/openjdk

ENV JAVA_HOME="/opt/java/openjdk" \
    PATH="/opt/java/openjdk/bin:${PATH}"

RUN python3 <<'PY'
import hashlib
import os
import urllib.request
import zipfile

version = os.environ.get("GHIDRA_VERSION", "12.0.4")
date = os.environ.get("GHIDRA_DATE", "20260303")
expected = os.environ.get("GHIDRA_ZIP_SHA256", "c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120")
url = f"https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_{version}_build/ghidra_{version}_PUBLIC_{date}.zip"
zip_path = "/tmp/ghidra.zip"

with urllib.request.urlopen(url) as response, open(zip_path, "wb") as out:
    digest = hashlib.sha256()
    while True:
        chunk = response.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        out.write(chunk)
actual = digest.hexdigest()
if actual != expected:
    raise SystemExit(f"Ghidra zip SHA256 mismatch: expected {expected}, got {actual}")

with zipfile.ZipFile(zip_path) as archive:
    for member in archive.infolist():
        target = os.path.abspath(os.path.join("/opt", member.filename))
        if not target.startswith("/opt/"):
            raise SystemExit(f"Unsafe zip member: {member.filename}")
    archive.extractall("/opt")
os.rename(f"/opt/ghidra_{version}_PUBLIC", "/opt/ghidra")
os.remove(zip_path)
PY
RUN chmod +x /opt/ghidra/support/analyzeHeadless \
    /opt/ghidra/support/launch.sh \
    /opt/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile

ARG JADX_VERSION
ARG JADX_ZIP_SHA256
RUN python3 <<'PY'
import hashlib
import os
import urllib.request
import zipfile

version = os.environ.get("JADX_VERSION", "1.5.4")
expected = os.environ.get("JADX_ZIP_SHA256", "f6f0d51a4af63e430045aa64c4f110b89b53e82eb596ccb3a4bd3f865adec70e")
url = f"https://github.com/skylot/jadx/releases/download/v{version}/jadx-{version}.zip"
zip_path = "/tmp/jadx.zip"
target_dir = "/opt/jadx"

with urllib.request.urlopen(url) as response, open(zip_path, "wb") as out:
    digest = hashlib.sha256()
    while True:
        chunk = response.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        out.write(chunk)
actual = digest.hexdigest()
if actual != expected:
    raise SystemExit(f"jadx zip SHA256 mismatch: expected {expected}, got {actual}")

os.makedirs(target_dir, exist_ok=True)
with zipfile.ZipFile(zip_path) as archive:
    for member in archive.infolist():
        target = os.path.abspath(os.path.join(target_dir, member.filename))
        if not target.startswith(target_dir + "/") and target != target_dir:
            raise SystemExit(f"Unsafe zip member: {member.filename}")
    archive.extractall(target_dir)
os.remove(zip_path)
PY
RUN chmod +x /opt/jadx/bin/jadx /opt/jadx/bin/jadx-gui || true

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY ghidra_scripts ./ghidra_scripts
COPY schemas ./schemas

RUN pip install --no-cache-dir .
RUN mkdir -p /home/app /input /output && chown -R 10001:0 /home/app /app /output

ENV PATH="/opt/ghidra/support:/opt/jadx/bin:${PATH}" \
    GHIDRA_HOME="/opt/ghidra" \
    GHIDRA_VERSION="${GHIDRA_VERSION}" \
    JADX_HOME="/opt/jadx" \
    JADX_VERSION="${JADX_VERSION}" \
    DECOMP_MCP_EXECUTION_MODE="direct" \
    DECOMP_MCP_INPUT_ROOT="/input" \
    DECOMP_MCP_OUTPUT_ROOT="/output" \
    DECOMP_MCP_GHIDRA_SCRIPT_DIR="/app/ghidra_scripts" \
    HOME="/home/app"

USER 10001
ENTRYPOINT ["decomp-mcp"]
