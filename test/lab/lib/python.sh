# shellcheck shell=bash
# The Python SDK on ligo1 (.specs/ligo-client-sdk-python.md PY-L1 to PY-L3): uv from the lab host, its own
# Python, a venv with the SDK's wheel and the dependencies it brings from PyPI (ligo1 reaches the internet
# through the VM's NAT, as it does for apt), the Python echo client and the helper of the Go lab tests.

PY_DIR=/opt/ligo-py
PY_HOME=/usr/local/lib/ligo-lab

# py_install: builds the wheel from this checkout and installs it on ligo1; run again after a change.
py_install() {
	section "The Python SDK on ligo1"
	local out="$LAB_STATE_DIR/python" uv wheel
	uv="$(command -v uv)" || die "uv is not installed on the lab host (https://docs.astral.sh/uv/)"
	rm -rf "$out"
	mkdir -p "$out"
	(cd "$REPO_DIR" && uv build --wheel --out-dir "$out" sdk/python) >/dev/null 2>&1 || die "cannot build the Python SDK's wheel"
	wheel="$(ls "$out"/*.whl)"
	inner_push "$uv" ligo1 /usr/local/bin/uv 0755
	inner_push "$wheel" ligo1 "/root/$(basename "$wheel")" 0644
	# Python is installed outside root's home, so that the workload's user can run it
	inner_exec ligo1 sh -ec "export UV_PYTHON_INSTALL_DIR=/opt/uv-python
		uv venv --quiet --python 3.12 $PY_DIR
		uv pip install --quiet --python $PY_DIR/bin/python --reinstall /root/$(basename "$wheel")
		chmod -R a+rX /opt/uv-python $PY_DIR" || die "cannot install the Python SDK on ligo1 (does it reach PyPI?)"
	inner_exec ligo1 mkdir -p "$PY_HOME"
	inner_push "$REPO_DIR/test/lab/python/sdk_check.py" ligo1 "$PY_HOME/sdk_check.py" 0644
	inner_push "$REPO_DIR/test/lab/echo/client-py/echo_client.py" ligo1 /usr/local/bin/echo-client-py 0755
	info "ligo-client $(inner_exec ligo1 "$PY_DIR/bin/python" -c 'import importlib.metadata as m; print(m.version("ligo-client"))') on ligo1, Python $(inner_exec ligo1 "$PY_DIR/bin/python" -V)"
}
