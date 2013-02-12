.PHONY: echelon-encrypted
echelon-encrypted: encrypted.eml
	cat $< | ../../../../manage ud-echelon --dryrun

.PHONY: echelon-plaintext
echelon-plaintext: plaintext.eml
	cat $< | ../../../../manage ud-echelon --dryrun

.PHONY: mailgate
mailgate: encrypted.eml
	cat $< | ../../../../manage ud-mailgate --dryrun --console

.PHONY: clean
clean:
	rm -f *.eml *.pyc

plaintext.eml: commands.txt
	cat $< | ./fakemail -s 'another test' changes@db.debian.org > $@

encrypted.eml: commands.txt
	cat $< | gpg --sign --armor | ./fakemail -s 'another test' changes@db.debian.org > $@
