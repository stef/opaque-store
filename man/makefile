all: opaquestore.1 opaqueztore.1 opaque-store.cfg.1 opaque-stored.cfg.1

install: $(PREFIX)/share/man/man1/opaquestore.1 $(PREFIX)/share/man/man1/opaqueztore.1 \
	      $(PREFIX)/share/man/man5/opaque-store.cfg.1 $(PREFIX)/share/man/man5/opaque-stored.cfg.1 \

clean:
	rm -f *.1

%.1: %.md
	cp $(@:.1=.head) $@
	cmark -t man $< >>$@
