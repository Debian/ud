.PHONY: build
build: commands.eml
	@#cat $< | ../../../../manage mailgate --settings=ud.local --console
	cat $< | ../../../../manage mailgate --console --dryrun

.PHONY: clean
clean:
	rm -f *.eml *.pyc

commands.eml: commands.txt
	cat $< | gpg --sign --armor | ./fakemail -s 'another test' changes@db.debian.org > $@
