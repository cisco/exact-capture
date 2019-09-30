all: docs	
.PHONY all:

test: 
	mkdocs serve

publish:
	mkdocs gh-deploy

docs:
	mkdocs build --clean

clean:
	rm -rf site

