paper: paper-clean paper-build

paper-build:
	mkdir -p build
	latexmk -pdf -bibtex -outdir=../build -cd docs/paper.tex
	cp build/paper.pdf docs
	rm -rf build

paper-clean:
	rm -f build/*

.PHONY: paper-clean paper-build
