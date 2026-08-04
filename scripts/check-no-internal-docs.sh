#!/usr/bin/env bash
# Pre-push gate: run before every push to main. Mirrors the checks in
# .github/workflows/no-internal-docs.yml so a leak is caught locally,
# not just after it reaches GitHub.
#
# Reads git's real pre-push hook protocol on stdin (lines of
# "<local ref> <local sha1> <remote ref> <remote sha1>") and diffs the
# actual commits about to be pushed. `git diff --cached` is NOT usable
# here: the index is empty by the time a push happens (commit clears
# staging), so a --cached check silently passes on every push
# regardless of content -- confirmed dead code in an earlier version
# of this script (see WorkloadTruth's fixed version, same discipline).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

PATTERN='CEO review|office.?hours|eng.?review|devex review|CSO review|CSO threat.?model|/oss-[0-9]+-[a-z-]+|/plan-eng-review|/review finding|Reviewer Concern|viability score|WOUNDED|fundrais|investor.?outreach|Show HN draft|hype.?seed'
ZERO_SHA="0000000000000000000000000000000000000000"
# The fixed, well-known hash of git's empty tree object -- exists in every
# repo without needing to be created. Used as the diff base for a brand-new
# branch/tag push below.
EMPTY_TREE="4b825dc642cb6eb9a060e54bf8d69288fbee4904"
forbidden_files=""
hits=""

while read -r local_ref local_sha remote_ref remote_sha; do
  [ "$local_sha" = "$ZERO_SHA" ] && continue # deleting a ref, nothing to check
  if [ "$remote_sha" = "$ZERO_SHA" ]; then
    # New branch/tag: there is no remote commit to diff against, so a
    # naive `range="$local_sha"` (as an earlier version of this script
    # used) makes `git diff "$range"` compare the *working tree* to that
    # commit, not the commit's own content -- with a clean working tree
    # (the normal state at push time) that diff is always empty, so the
    # entire first push of a new branch silently skipped every check
    # below. Confirmed: this exact bug let real internal-process language
    # ship in this repo's very first commits, caught only by the separate
    # GitHub Actions job (which greps the full tree, not a diff) failing
    # after the push already landed. Diffing against the empty tree
    # instead makes every file in the new branch show up as newly added,
    # which is the actually-correct "check everything being introduced"
    # behavior the original comment claimed but didn't implement.
    range="$EMPTY_TREE..$local_sha"
  else
    range="$remote_sha..$local_sha"
  fi

  files=$(git diff --name-only "$range" -- . 2>/dev/null | grep -E '^(CLAUDE\.md|TODOS\.md|BRANCH_PROTECTION\.md|docs/branch-protection\.md|docs/security-review-.*\.md|docs/launch/.*|docs/.*preprint.*)$' || true)
  [ -n "$files" ] && forbidden_files="$forbidden_files
$files"

  matches=$(git diff "$range" -- . ':!scripts/check-no-internal-docs.sh' ':!.github/workflows/no-internal-docs.yml' | grep -inE "$PATTERN" || true)
  [ -n "$matches" ] && hits="$hits
$matches"
done

if [ -n "$forbidden_files" ]; then
  echo "BLOCKED: internal-only file(s) being pushed to this public repo:"
  echo "$forbidden_files"
  exit 1
fi

if [ -n "$hits" ]; then
  echo "BLOCKED: internal-process language in commits being pushed:"
  echo "$hits"
  exit 1
fi

echo "no-internal-docs check passed."
