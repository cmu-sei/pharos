#!/usr/bin/bash

# Include the following lines in your XSB script:
#DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
#source "$DIR/../helper.bash" "$DIR"

# And this script will ensure that xwam files are removed, that XSB is
# run from the correct location, etc.
$DIR = ${BASH_SOURCE[0]}

rm -f $DIR/*.xwam
cd "$DIR"
XSB="${XSB:-/usr/local/xsb-3.7.0/bin/xsb}"
