.PHONY: build
build: commands.eml
	cat $< | ../../../../manage mailgate --stdout

.PHONY: clean
clean:
	rm -f *.eml *.pyc

commands.eml: commands.txt
	cat $< | gpg --sign --armor | ./fakemail -s 'another test' changes@db.debian.org > $@
