#!/usr/bin/env bash
# =============================================================================
# tools/integration/probe_sibling_versions.sh — report each libs/* submodule
# pin vs what upstream currently offers (latest tag + tracked-branch head).
#
# Phase E tooling: cron/CI-friendly staleness probe so a sibling release
# doesn't sit unnoticed. Read-only — only `git ls-remote` network calls.
#
# Output: one block per submodule with the pinned SHA, the newest upstream
# tag (peeled to its commit), the tracked branch head, and a verdict:
#   UP-TO-DATE  pin equals the tracked branch head
#   STALE       upstream branch has moved past the pin
#
# Exit codes: 0 all pins up-to-date, 2 at least one STALE, 1 usage/plumbing
# error. Pass --no-fail to always exit 0 (marker-only mode for wrappers that
# treat any non-zero as a plumbing failure).
# =============================================================================
set -euo pipefail

NO_FAIL=0
[[ "${1:-}" == "--no-fail" ]] && NO_FAIL=1

cd "$(git rev-parse --show-toplevel)"

stale=0

# .gitmodules keys look like: submodule.libs/x25519.path libs/x25519
while read -r key path; do
    name=${key#submodule.}
    name=${name%.path}
    url=$(git config -f .gitmodules "submodule.${name}.url")
    branch=$(git config -f .gitmodules "submodule.${name}.branch" || echo HEAD)

    pinned=$(git ls-tree HEAD "$path" | awk '{print $3}')
    if [[ -z "$pinned" ]]; then
        echo "error: no gitlink for $path in HEAD" >&2
        exit 1
    fi

    remote_refs=$(git ls-remote --tags "$url")
    branch_head=$(git ls-remote "$url" "refs/heads/${branch}" | cut -f1)

    # Newest tag by version sort; resolve annotated tags via their ^{}
    # peeled entry so we compare commit SHAs, not tag-object SHAs.
    latest_tag=$(sed -n 's#.*\trefs/tags/##p' <<<"$remote_refs" \
                 | grep -v '\^{}$' | sort -V | tail -1)
    if [[ -n "$latest_tag" ]]; then
        tag_commit=$(awk -v t="refs/tags/${latest_tag}^{}" '$2==t{print $1}' <<<"$remote_refs")
        [[ -z "$tag_commit" ]] && \
            tag_commit=$(awk -v t="refs/tags/${latest_tag}" '$2==t{print $1}' <<<"$remote_refs")
    else
        latest_tag="(none)"
        tag_commit=""
    fi

    pin_short=${pinned:0:7}
    echo "${path}:"
    echo "  pinned:      ${pin_short}"
    if [[ -n "$tag_commit" ]]; then
        tag_note=$([[ "$tag_commit" == "$pinned" ]] && echo " (== pin)" || echo "")
        echo "  latest tag:  ${latest_tag} @ ${tag_commit:0:7}${tag_note}"
    else
        echo "  latest tag:  ${latest_tag}"
    fi
    if [[ "$branch_head" == "$pinned" ]]; then
        echo "  branch head: ${branch} @ ${branch_head:0:7}"
        echo "  verdict:     UP-TO-DATE"
    else
        echo "  branch head: ${branch} @ ${branch_head:0:7}"
        echo "  verdict:     STALE — upstream ${branch} has moved past the pin"
        stale=1
    fi
    echo
done < <(git config -f .gitmodules --get-regexp '^submodule\..*\.path$')

if (( stale )); then
    echo "RESULT: STALE pin(s) found — see verdicts above."
    (( NO_FAIL )) && exit 0
    exit 2
fi
echo "RESULT: all submodule pins match their tracked branch heads."
