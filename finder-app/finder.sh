#!/bin/sh

if [[ "$#" -ne 2 ]]; then
	echo "Useage: finder.sh /path/to/search searchstr"
	exit 1
fi

DIR="$1"
SEARCH="$2"

if [[ ! -d "$1" ]]; then
	echo "$1 does not exist."
	exit 1
fi

printf "The number of files are %d and the number of matching lines are %d"  "$(grep -Rl $2 $1 | wc -l)" "$(grep -R $2 $1 | wc -l)"

exit 0
