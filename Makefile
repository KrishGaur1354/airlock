JETSON ?= $(shell grep ^JETSON= airlock.conf 2>/dev/null | cut -d= -f2)
deploy:
	rsync -az --exclude .git --exclude out --exclude airlock.conf --exclude keys/airlock.key ./ $(JETSON):~/airlock/
remote:
	ssh $(JETSON) 'cd ~/airlock && $(CMD)'
demo:
	scripts/demo.sh
tamper:
	python3 scripts/tamper.py out/qwen3.airlock && python3 -m airlock import out/qwen3.tampered.airlock || true
test:
	@! grep -rn GMI airlock/gateway.py airlock/evidence.py airlock/bundle.py 2>/dev/null | grep -q . && echo "ok: high side is GMI-free"
