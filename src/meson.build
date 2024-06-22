libgcryptdep = dependency('libgcrypt')
src = 'crypto.c ioport.c psafe.c pws3.c util.c'.split()
executable('psafe', src, dependencies: [libgcryptdep])
