psafe
=====

![CMake on Single Platform](https://github.com/mockbutler/psafe/actions/workflows/cmake-single-platform.yml/badge.svg)

Comand line utility for dumpinging the contents of [Password Safe][pwsafe] database on Mac and Linux.

Building
--------

Requires

 * Compiler that supports C17.
 * [CMake][cmake]
 * [GCrypt Library][libgcrypt]

Setup

`cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Debug -G Ninja -B build`

[pwsafe]: http://pwsafe.org/
[cmake]: http://www.cmake.org/
[libgcrypt]: http://www.gnu.org/software/libgcrypt/
