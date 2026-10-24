# User Manual

## Install
No dependencies. Requires Python 3.8+.

## CLI
```
python takeoverhunter.py -l hosts.txt
python takeoverhunter.py -d example.com
python takeoverhunter.py -u sub.example.com
python takeoverhunter.py -l hosts.txt --json out.json --csv out.csv --report out.md --html out.html
python takeoverhunter.py -d example.com --threads 30 --timeout 10
```

## Web dashboard
```
python takeoverhunter.py --serve --port 8765
```
Open http://127.0.0.1:8765

## Tests
```
python -m pytest tests/ -q
```

## Docker
```
docker build -t takeoverhunter .
docker run -p 8765:8765 takeoverhunter
```
