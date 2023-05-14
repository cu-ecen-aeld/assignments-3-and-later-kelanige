#!/usr/bin/env bash
if [[ "$#" -ne 2 ]]; then
	echo "Usage: ./writer.sh /path/to/file output"
	exit 1
fi

install -D /dev/null "$1"
echo "$2" > "$1"
exit 0

