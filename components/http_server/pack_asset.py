#!/usr/bin/env python3
"""Minify and gzip a web asset for embedding in the firmware image.

Comments and indentation are worth keeping in components/http_server/www/ —
they are the only explanation of why the stylesheet is shaped the way it is —
but they are dead weight in flash, where the OTA slot is the binding
constraint. So they live in the source and are stripped here, on the way in.

Usage: pack_asset.py <input> <output.gz>

gzip mtime is pinned to 0 so identical input produces an identical artifact
and incremental builds stay reproducible.
"""

import gzip
import re
import sys


def minify_css(src):
    """Strip comments and redundant whitespace.

    String literals are copied through untouched: `content: " · "` depends on
    the space inside the quotes, and collapsing it would silently change the
    rendered separator.
    """
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in '"\'':
            j = i + 1
            while j < n:
                if src[j] == '\\':
                    j += 2
                    continue
                if src[j] == c:
                    break
                j += 1
            out.append(src[i:j + 1])
            i = j + 1
        elif src.startswith('/*', i):
            end = src.find('*/', i + 2)
            i = n if end == -1 else end + 2
        else:
            out.append(c)
            i += 1

    css = ''.join(out)
    css = re.sub(r'\s+', ' ', css)
    # Safe to tighten around structural punctuation: selectors and declarations
    # never depend on whitespace next to these. Descendant combinators (a plain
    # space between selectors) are preserved by the \s+ collapse above.
    css = re.sub(r'\s*([{}:;,>])\s*', r'\1', css)
    css = css.replace(';}', '}')
    return css.strip()


def minify_js(src):
    """Drop comments and indentation only.

    Deliberately conservative: collapsing statements risks automatic semicolon
    insertion changing behaviour, and this file is under a kilobyte, so the
    remaining newlines cost almost nothing after gzip.
    """
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in '"\'`':
            j = i + 1
            while j < n:
                if src[j] == '\\':
                    j += 2
                    continue
                if src[j] == c:
                    break
                j += 1
            out.append(src[i:j + 1])
            i = j + 1
        elif src.startswith('/*', i):
            end = src.find('*/', i + 2)
            i = n if end == -1 else end + 2
        elif src.startswith('//', i):
            # Only a comment when it starts the line; otherwise it may be the
            # tail of a URL, and this file has no trailing-comment convention.
            line_start = src.rfind('\n', 0, i) + 1
            if src[line_start:i].strip() == '':
                end = src.find('\n', i)
                i = n if end == -1 else end
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1

    lines = [ln.strip() for ln in ''.join(out).split('\n')]
    return '\n'.join(ln for ln in lines if ln)


def minify_svg(src):
    src = re.sub(r'<!--.*?-->', '', src, flags=re.S)
    return re.sub(r'>\s+<', '><', src).strip()


def main():
    if len(sys.argv) != 3:
        sys.exit('usage: pack_asset.py <input> <output.gz>')

    src_path, dst_path = sys.argv[1], sys.argv[2]
    with open(src_path, encoding='utf-8') as f:
        src = f.read()

    if src_path.endswith('.css'):
        packed = minify_css(src)
    elif src_path.endswith('.js'):
        packed = minify_js(src)
    elif src_path.endswith('.svg'):
        packed = minify_svg(src)
    else:
        packed = src

    with open(dst_path, 'wb') as f:
        f.write(gzip.compress(packed.encode('utf-8'), 9, mtime=0))


if __name__ == '__main__':
    main()
