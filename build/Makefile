# Makefile para capp - Cybersecurity App Suite 


PYTHON = python
PACKAGE = capp
MAIN_SCRIPT = modules/app.py
install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	$(PYTHON) -m unittest discover tests

run:
	$(PYTHON) $(PACKAGE)/$(MAIN_SCRIPT)

clean:
	rm -rf __pycache__ 
	rm -rf *.pyc
	rm -rf .coverage
	rm -rf htmlcov

.PHONY: install test run clean
