paper: paper-clean paper-build

paper-build:
	@mkdir -p build
	@latexmk -pdf -bibtex -outdir=../build -cd docs/paper.tex
	@cp build/paper.pdf docs
	@rm -rf build

paper-clean:
	@rm -f build/*

test:
	@go test -v ./...

run:
	@go run .

.PHONY: paper-clean paper-build
