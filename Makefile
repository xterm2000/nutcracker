.PHONY: help run modules args audit script dict clean

# crack.py exits 3 on a legit NOT-FOUND (0 = cracked, 1 = real error, 2 = bad
# CLI args). For the run-a-crack targets a NOT-FOUND must not fail Make.
# Usage: <cmd> ; $(call keep3)
keep3 = rc=$$?; [ $$rc -eq 0 ] || [ $$rc -eq 3 ] || exit $$rc

help:
	@echo "Targets:"
	@echo "  make run ARGS=\"-p 'Summer2024!'\"   run crack.py with ARGS"
	@echo "  make modules                         list available attack modules"
	@echo "  make args                            list crack.py's CLI flags (--help)"
	@echo "  make audit                           quick self-test against a known weak password"
	@echo "  make script                          run test.sh"
	@echo "  make dict                            dictionaries used"
	@echo "  make clean                           remove __pycache__ dirs"

run:
	@./crack.py $(ARGS); $(call keep3)

modules:
	./crack.py --list-modules

args:
	./crack.py --help

audit:
	@./crack.py -p 'password123' --module-budget 100k --budget 500k; $(call keep3)

script:
	@./test.sh; $(call keep3)

dict:
	ls -l ./data 


clean:
	find . -type d -name '__pycache__' -exec rm -rf {} +
