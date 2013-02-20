PROJECT_DIR=../../../..

.PHONY: all
all: echelon-encrypted echelon-plaintext mailgate

.PHONY: echelon-encrypted
echelon-encrypted: encrypted.eml
	cat $< | $(PROJECT_DIR)/manage ud-echelon --config secrets.yaml --dryrun

.PHONY: echelon-plaintext
echelon-plaintext: plaintext.eml
	cat $< | $(PROJECT_DIR)/manage ud-echelon --config secrets.yaml --dryrun

.PHONY: mailgate
mailgate: encrypted.eml
	cat $< | $(PROJECT_DIR)/manage ud-mailgate --dryrun --console

.PHONY: clean
clean:
	rm -f *.eml *.pyc

plaintext.eml: commands.txt
	cat $< | ./fakemail -s 'another test' changes@db.debian.org > $@

encrypted.eml: commands.txt
	cat $< | gpg --sign --armor | ./fakemail -s 'another test' changes@db.debian.org > $@
