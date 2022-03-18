find_path(CRYPTOPP_INCLUDE_DIR cryptlib.h HINTS /usr/include/crypto++)

find_library(CRYPTOPP_LIBRARIES crypto++ cryptopp)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Cryptopp DEFAULT_MSG CRYPTOPP_LIBRARIES CRYPTOPP_INCLUDE_DIR)

mark_as_advanced(CRYPTOPP_LIBRARIES CRYPTOPP_INCLUDE_DIR)

