.PHONY: test serve
test:
	python -m pytest tests/ -q
serve:
	python takeoverhunter.py --serve --port 8765
scan:
	python takeoverhunter.py -d example.com
