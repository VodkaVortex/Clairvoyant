import re, os, sys

def read(f, root):
    try:
        return open(os.path.join(root,f),errors="ignore").read().split("\n")
    except: return []

def strip_comments_strings(src):
    # remove block comments, line comments, and string/char literals but keep newlines
    out=[]
    i=0; n=len(src); mode=None
    while i<n:
        c=src[i]
        nxt=src[i+1] if i+1<n else ""
        if mode is None:
            if c=="/" and nxt=="*": mode="block"; out.append("  "); i+=2; continue
            if c=="/" and nxt=="/": mode="line"; out.append("  "); i+=2; continue
            if c=='"': mode="str"; out.append(" "); i+=1; continue
            if c=="'": mode="chr"; out.append(" "); i+=1; continue
            out.append(c); i+=1; continue
        if mode=="block":
            if c=="*" and nxt=="/": mode=None; out.append("  "); i+=2; continue
            out.append("\n" if c=="\n" else " "); i+=1; continue
        if mode=="line":
            if c=="\n": mode=None; out.append("\n")
            else: out.append(" ")
            i+=1; continue
        if mode=="str":
            if c=="\\": out.append("  "); i+=2; continue
            if c=='"': mode=None; out.append(" "); i+=1; continue
            out.append("\n" if c=="\n" else " "); i+=1; continue
        if mode=="chr":
            if c=="\\": out.append("  "); i+=2; continue
            if c=="'": mode=None; out.append(" "); i+=1; continue
            out.append("\n" if c=="\n" else " "); i+=1; continue
    return "".join(out)

def find_all_funcs(lines_stripped):
    """Return dict funcname -> (start_line_0based, end_line_0based) for all definitions."""
    funcs={}
    n=len(lines_stripped)
    i=0
    while i<n:
        l=lines_stripped[i]
        m=re.match(r'^([A-Za-z_][A-Za-z0-9_ \t\*]*?)\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', l)
        if m and not re.match(r'^\s*(if|for|while|switch|return|sizeof|else|do)\b', l):
            name=m.group(2)
            # find opening brace on this or subsequent lines; abort on ';' first
            j=i; buf=""; found=False
            while j<n and j<i+15:
                buf+=lines_stripped[j]
                if "{" in lines_stripped[j]:
                    # must not have ';' before '{' on the segment... prototypes end with ;
                    seg="".join(lines_stripped[i:j+1])
                    br=seg.find("{")
                    semi=seg.find(";")
                    if semi!=-1 and semi<br:
                        break
                    found=True
                    break
                if ";" in lines_stripped[j]:
                    break
                j+=1
            if found:
                # brace match
                depth=0; k=j; ok=False
                while k<n:
                    depth+=lines_stripped[k].count("{")-lines_stripped[k].count("}")
                    if depth<=0:
                        ok=True; break
                    k+=1
                if ok:
                    # avoid duplicates: keep first
                    if name not in funcs or funcs[name][0]>i:
                        funcs.setdefault(name,(i,k))
                    i=k+1; continue
        i+=1
    return funcs
