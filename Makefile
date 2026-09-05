.PHONY: help run modules args audit clean

help:
	@echo "Targets:"
	@echo "  make run ARGS=\"-p 'Summer2024!'\"   run crack.py with ARGS"
	@echo "  make modules                        list available attack modules"
	@echo "  make args                            list crack.py's CLI flags (--help)"
	@echo "  make audit                          quick self-test against a known weak password"
	@echo "  make clean                           remove __pycache__ dirs"

run:
	./crack.py $(ARGS)

modules:
	./crack.py --list-modules

args:
	./crack.py --help

audit:
	./crack.py -p 'password123' --module-budget 100k --budget 500k

clean:
	find . -type d -name '__pycache__' -exec rm -rf {} +
