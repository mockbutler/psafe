libgcryptdep = dependency('libgcrypt')
src = 'crypto.c ioport.c psafe.c pws3.c util.c'.split()
executable('psafe', src, dependencies: [libgcryptdep])

util_test = executable('test_util', ['test_util.c', 'util.c'])
test('utility', util_test)
