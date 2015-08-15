psafe
=====

Dump Password Safe V3 database from the command line.

Dump the contents of [Password Safe][passwordsafe] database.

The sole library dependency for the project is:
[libgcrypt](http://www.gnu.org/software/libgcrypt/).

I've checked in to this project relevant documents from both
[Password Safe][passwordsafe] project and IETF.

Building
--------

Prerequisites:

 * [CMake][cmake]
 * [GCrypt Library][libgcrypt]

I recommend an out-of-source build. For example:

    git clone psafe-url psafe
    mkdir psafe-build
    cd psafe-build
    cmake ../psafe
    make

Alternatives
------------

* [OPWS](http://www.panix.com/~mbac/opws.md)
* [pwsafe password safe database](http://nsd.dyndns.org/pwsafe/) Note:
  V1 and V2 **only**.

[passwordsafe]: http://pwsafe.org/
[cmake]: http://www.cmake.org/
[libgcrypt]: http://www.gnu.org/software/libgcrypt/
