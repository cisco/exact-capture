env = pipenv run


all: docs	
.PHONY all:


test: 
	$(env) mkdocs serve

publish:
	$(env) mkdocs gh-deploy

docs:
	$(env) mkdocs build --clean

clean:
	rm -rf site

