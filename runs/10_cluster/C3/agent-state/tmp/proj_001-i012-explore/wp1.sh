#!/bin/bash
# Extract enclosing function for file:line using brace-depth scan.
f="$1"; l="$2"
awk -v line="$l" '
NR==line { found=1 }
!found && /^[a-zA-Z_].*\(/ && !/^\s/ {
  # candidate function start line at column 0
  fn=NR; name=$0
}
found { exit }
END {}
' "$f" >/dev/null
awk -v target="$l" '
NR<=target {
  line=$0
  if (NR<target && line ~ /^[a-zA-Z_].*\(/ && line !~ /^[ \t]/ && line !~ /^;/) { fnstart=NR; fnline=line }
}
NR==target { print "FUNC_START:" fnstart; print "FUNC_LINE:" fnline; exit }
' "$f"
