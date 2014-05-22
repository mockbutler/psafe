psafe
=====

Access Password Safe V3 database from the command line.

Dump the contents of [Password Safe][passwordsafe] database.

The sole library dependency for the project is:
[libgcrypt](http://www.gnu.org/software/libgcrypt/).

I've checked in to this project relevant documents from both
[Password Safe][passwordsafe] project and IETF.

Building
--------

Should build on any modern linux, assuming you ensure that a modern
version of libgcrypt is installed. Just run `make`.

Warnings
--------

* As it stands: the password must be supplied on the command
  line. Needless to say **do not use on a multi-user system**.
* Rife with bugs including memory leaks.

Alternatives
------------

* [OPWS](http://www.panix.com/~mbac/opws.md)
* [pwsafe password safe database](http://nsd.dyndns.org/pwsafe/) Note:
  V1 and V2 **only**.

[passwordsafe]: http://pwsafe.org/


