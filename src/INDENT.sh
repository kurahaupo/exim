#!/bin/sh

# The indenting style used by Exim is somewhat unusual:
#    -> the {} surrounding any code are indented to the same level as the code
#       itself
#         (and the semantic level of that code determines its indentation without
#         counting brackets)
#    -> the body of a function is NOT indented
#
# Sadly .indent.pro has no "comment" syntax, so instead we have this script
# with comments to generate it.

grep -v -e '^#' -e '^$' <<EOF > .indent.pro

# indent using tabstops every 8 chars
-ts8

# put { on line after function definition
-blf

# don't indent within braces
-bli0

# extra indenting for arithmetic grouping

# don't line up function parameters (pretty please can we change this?!?)
-nlp

# leave spacing in preprocessor lines
-lps

# hanging unindent for goto labels
-il -2

# hanging unindent for case labels
-cli 0

# no space between cast or function call and its operand/parameters
-ncs
#--no-space-after-casts
-npcs
#--no-space-after-function-call-names
#--no-space-after-procedure-calls

# space after if/for/switch/while
-saf
#--space-after-for
-sai
#--space-after-if
-saw
#--space-after-while

# no space on interior of parentheses
-nprs
#--no-space-after-parentheses

EOF

echo "$PWD/.indent.pro has been updated"
echo "Now run: indent *.[ch] */*.[ch] */*/*.[ch]"
