#!/bin/sh
# load_dyn('${2}') could be expected facts (in typerules.pl): 
rm -f *.xwam

# if [["$2" == "stat"]]
# then
/data/shared/research/XSB/bin/xsb -e "[typerules], load_dyn('${1}'), report, stats."
# fi
# if [["$2" == "validate"]]
# then
#     /data/shared/research/XSB/bin/xsb -e "[typerules], load_dyn('${1}'), report, [validate], validate, halt."
# else
#     /data/shared/research/XSB/bin/xsb -e "[typerules], load_dyn('${1}'), report, halt."
# fi

