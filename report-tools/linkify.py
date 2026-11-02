"""Make issue/PR references and section references clickable in the report markdown.

- `#NNNN` (not already inside a markdown link) -> [#NNNN](repo/pull/NNNN) if NNNN is a known PR, else repo/issues/NNNN
  (GitHub redirects /issues/N to /pull/N when N is a PR, so unknown numbers are safe).
- `§N` / `§N.M` / `§N–M` -> link to the heading anchor using GitHub-style slugs, which the PDF build replicates.
"""
import re, sys, json, glob
REPO = "https://github.com/dsx-ai-factory/infra-controller"
path = sys.argv[1]
scratch = sys.argv[2]
text = open(path).read()

# --- known PR numbers (open + recently merged) ---
prs = set()
for f in glob.glob(f"{scratch}/gh/prs*.json") + glob.glob(f"{scratch}/gh/merged*.json"):
    try:
        for row in json.load(open(f)):
            prs.add(int(row["number"]))
    except Exception:
        pass
# PR numbers referenced in text as "PR #N" / "PRs N" are PRs too
for m in re.finditer(r"\bPRs? #?(\d{3,5})", text):
    prs.add(int(m.group(1)))
for m in re.finditer(r"\(PRs? (\d{3,5})(?:,| and| or)", text):
    prs.add(int(m.group(1)))

# --- GitHub-style slugs for headings ---
def gh_slug(title):
    s = title.strip().lower()
    s = re.sub(r"[^\w\s\-]", "", s, flags=re.UNICODE)   # drop punctuation except hyphen
    s = re.sub(r"\s", "-", s)
    return s
headings = {}
seen = {}
for line in text.splitlines():
    m = re.match(r"^(#{1,6})\s+(.*)$", line)
    if not m: continue
    title = m.group(2).strip()
    # strip inline code backticks and markdown links for slug purposes (GitHub keeps text)
    plain = re.sub(r"`([^`]*)`", r"\1", title)
    plain = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", plain)
    slug = gh_slug(plain)
    n = seen.get(slug, 0)
    seen[slug] = n + 1
    if n: slug = f"{slug}-{n}"
    num = re.match(r"^(\d+(?:\.\d+)?)\.?\s", plain)
    if num:
        headings[num.group(1)] = slug
    if plain.startswith("Appendix A"):
        headings["A"] = slug

# --- protect existing links and code spans ---
protected = []
def protect(m):
    protected.append(m.group(0))
    return f"\x00{len(protected)-1}\x00"
work = re.sub(r"\[[^\]]*\]\([^)]*\)|`[^`\n]*`|^```.*?^```", protect, text, flags=re.S | re.M)

# --- issue / PR refs ---
def link_num(m):
    n = int(m.group(1))
    kind = "pull" if n in prs else "issues"
    return f"[#{n}]({REPO}/{kind}/{n})"
work = re.sub(r"(?<![\w/\[])#(\d{2,5})\b", link_num, work)

# --- section refs: §N, §N.M, and ranges §N–M / §N-M ---
def link_sec(m):
    whole = m.group(0)
    a, b = m.group(1), m.group(3)
    if a not in headings:
        return whole
    first = f"[§{a}](#{headings[a]})"
    if b and b in headings:
        return f"{first}{m.group(2)}[§{b}](#{headings[b]})"
    return first + (m.group(2) + m.group(3) if b else "")
work = re.sub(r"§(\d+(?:\.\d+)?)(?:([–\-])(\d+(?:\.\d+)?))?", link_sec, work)

# --- restore protected ---
def restore(m):
    return protected[int(m.group(1))]
work = re.sub(r"\x00(\d+)\x00", restore, work)
open(path, "w").write(work)
print("headings indexed:", len(headings), "| known PRs:", len(prs))
print("issue/PR links:", len(re.findall(r"\]\(" + re.escape(REPO) + r"/(?:issues|pull)/\d+\)", work)), "| section links:", len(re.findall(r"\[§[\d.]+\]\(#", work)))
