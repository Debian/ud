.PHONY: build
build: commands.eml
	@#cat $< | ../../../../manage mailgate --settings=ud.local --stdout
	cat $< | ../../../../manage mailgate --stdout --dryrun

.PHONY: clean
clean:
	rm -f *.eml *.pyc

commands.eml: commands.txt
	cat $< | gpg --sign --armor | ./fakemail -s 'another test' changes@db.debian.org > $@
