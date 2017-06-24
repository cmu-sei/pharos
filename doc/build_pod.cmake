# This is used by the build_pharos_pod() command, which is implemented
# in cmake/BuildPharosPod.cmake.

file(READ "${POD_DIR}/pharos_env.pod" PHAROS_ENV_POD)
file(READ "${POD_DIR}/pharos_files.pod" PHAROS_FILES_POD)
file(READ "${POD_DIR}/pharos_options.pod" PHAROS_OPTIONS_POD)
configure_file(${POD_SOURCE} ${POD_DEST} @ONLY NEWLINE_STYLE LF)
