# ud

A reimplementation of Debian's userdir-ldap, leveraging the Django framework.

The Debian Project operates a number of servers (physical and virtual) in data
centres located around the world (primarily in Europe and North America).

User, Group and Host entries are stored in an LDAP database on a 'master' server
from whence they are extracted (ud-generate) into a number of text files that
are securely copied (ud-replicate) to 'slave' servers where they are consumed by
various services.

End users are able to update/delete specific fields in their User entries by
sending gpg-signed commands to a utility (ud-mailgate) that (a) verifies the
gpg signature, (b) fetches the User object based on the gpg fingerprint, (c)
validates &amp; processes each update/delete request contained in the signed
message, (d) saves the changes to the User object back in the LDAP database and
(e) sends an email back to the end user.

Administrators are able to ensure the validity of a single (or of every) User
entry in the LDAP database via a utility (ud-validate) that runs the validators
associated with the User model. Administrators may use a readline-oriented
command processors to modify Group (ud-modgroup), Host (ud-modhost) and User
(ud-moduser) entries.

In an effort to identify Debian Developers who are MIA (Missing In Action), a
utility (ud-echelon) is able to extract identifying information (either from the
fingerprint of the gpg signature or from the 'From' header) from emails sent
to it.  The Debian Project attaches this utility to all @lists.debian.org mailing
lists.

Finally, a finger daemon (ud-fingerd) returns public attributes including the
gpg key pointed to by to PKA DNS records (eg: dig lfilipoz._pka.debian.org).
