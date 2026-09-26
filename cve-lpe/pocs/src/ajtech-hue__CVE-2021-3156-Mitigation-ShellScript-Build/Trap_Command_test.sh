#!/bin/bash
@Authors: Anurag Jena
Date: 29/04/2021                                                                                                                                                                                                                                                 #!/bin/bash

function myfunc ()
{
    if test "$BASH_COMMAND" = "echo 1"; then
        $BASH_COMMAND
        echo "runing after 'echo 1'"
        return 1
    else
        return 0
    fi
}

shopt -s extdebug
trap "myfunc" DEBUG

echo 1
echo 2
