// Copyright 2020 Carnegie Mellon University.  See LICENSE file for terms.

#include <libpharos/options.hpp>
#include <libpharos/descriptors.hpp>

using namespace pharos;

static int partition_main(int argc, char **argv) {
  ProgOptVarMap vm = parse_cert_options(
    argc, argv, cert_standard_options(),
    R"(partition does function partitioning of a binary and writes the information
to a file, usually with the "serialized" extension.  This serialized file
can then be used as the input to other pharos programs using the
--serialize option, allowing them to load the serialized file instead of
doing the function partitioning from scratch.)");
  partition(vm);
  return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
  return pharos_main("PART", partition_main, argc, argv, STDERR_FILENO);
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
