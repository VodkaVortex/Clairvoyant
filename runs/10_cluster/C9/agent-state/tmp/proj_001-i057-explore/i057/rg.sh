#!/bin/bash
# minimal recursive grep with extended regex; args: PATTERN PATH...
PAT="$1"; shift
grep -rEn --include='*.c' --include='*.h' --include='*.cpp' -- "$PAT" "$@"
