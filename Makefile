.PHONY: all clean install build

PREFIX ?= /usr/local
NAME = otter
CONF_FLAGS ?=

setup.bin: setup.ml
	ocamlopt.opt -o $@ $< || ocamlopt -o $@ $< || ocamlc -o $@ $<
	rm -f setup.cmx setup.cmi setup.o setup.cmo

setup.data: setup.bin
	./setup.bin -configure $(CONF_FLAGS) --prefix $(PREFIX)

build: setup.data setup.bin
	./setup.bin -build -classic-display

install: setup.bin
	./setup.bin -install

uninstall: setup.bin
	./setup.bin -uninstall

reinstall: setup.bin
	ocamlfind remove $(NAME) || true
	./setup.bin -reinstall

clean:
	ocamlbuild -clean
	rm -f setup.data setup.log setup.bin
	find . -name "_build" -print0 | xargs -0 rm -rf