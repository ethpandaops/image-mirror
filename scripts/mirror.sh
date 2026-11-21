#!/usr/bin/env bash
# Verifies a mirror request and copies <SOURCE>/<IMAGE> to <DESTINATION>/<IMAGE>.
# RULE is the image's publishers as JSON. IMAGE and TAGS (tag@sha256:digest
# pairs) are untrusted. Credentials reach tools via stdin.
set -euo pipefail

fail() { echo "error: $*"; exit 1; }

[[ $IMAGE =~ ^[a-z0-9][a-z0-9._-]{0,127}$ ]] || fail "invalid image name"
[[ $REQUEST_ID =~ ^[A-Za-z0-9._-]{1,64}$ ]] || fail "invalid request_id"
[[ -n ${RULE:-} && -n ${SOURCE:-} && -n ${DESTINATION:-} ]] || fail "RULE, SOURCE and DESTINATION are required"
jq -e 'type == "array" and length > 0' <<<"$RULE" >/dev/null || fail "invalid RULE"
src="${SOURCE}/${IMAGE}"
dest="${DESTINATION}/${IMAGE}"

read -ra pairs <<<"$TAGS"
(( ${#pairs[@]} > 0 && ${#pairs[@]} <= 30 )) || fail "expected 1-30 tag@digest pairs"
declare -a tags digests
for p in "${pairs[@]}"; do
  tag=${p%%@*} digest=${p#*@}
  [[ $tag =~ ^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$ ]] || fail "invalid tag"
  [[ $digest =~ ^sha256:[a-f0-9]{64}$ ]] || fail "invalid digest for ${tag}"
  tags+=("$tag") digests+=("$digest")
done

for host in ${INSECURE_REGISTRIES:-}; do
  regctl registry set --tls disabled "$host" >/dev/null
done
if [[ -n ${SOURCE_TOKEN:-} ]]; then
  regctl registry login "${SOURCE%%/*}" -u "${SOURCE_USERNAME:-token}" --pass-stdin <<<"$SOURCE_TOKEN" >/dev/null
fi
if [[ -n ${DESTINATION_TOKEN:-} ]]; then
  regctl registry login "${DESTINATION%%/*}" -u "${DESTINATION_USERNAME:-token}" --pass-stdin <<<"$DESTINATION_TOKEN" >/dev/null
fi

regctl tag ls --limit 1 "$dest" >/dev/null 2>&1 || fail "${dest} does not exist"

# Every manifest behind every tag (index and per-arch manifests).
declare -A seen
tree() {
  local d=$1 body
  [[ -n ${seen[$d]:-} ]] && return 0
  seen[$d]=1
  body=$(regctl manifest get "${src}@${d}" --format raw-body)
  while read -r child; do
    [[ -n $child ]] && tree "$child"
  done < <(jq -r '(.manifests // [])[]
    | select((.annotations["vnd.docker.reference.type"] // "") != "attestation-manifest")
    | .digest' <<<"$body")
}

for i in "${!tags[@]}"; do
  current=$(regctl image digest "${src}:${tags[$i]}") || fail "${src}:${tags[$i]} not found"
  [[ $current == "${digests[$i]}" ]] || fail "${src}:${tags[$i]} is ${current}, not ${digests[$i]}"
  tree "${digests[$i]}"
done

gh_retry() {
  local i err
  err=$(mktemp)
  for i in $(seq 1 10); do
    if gh "$@" 2>"$err"; then rm -f "$err"; return 0; fi
    grep -qi 'rate limit' "$err" || { rm -f "$err"; return 1; }
    echo "GitHub API rate limited; retrying in 30s" >&2
    sleep 30
  done
  rm -f "$err"
  return 1
}

# Prints the certificate of an attestation for digest $2 that satisfies
# publisher $1, or fails.
authorise() {
  local pub=$1 d=$2 repo out="" s certs
  local -a signers
  repo=$(jq -r .repo <<<"$pub")
  mapfile -t signers < <(jq -r '(.signer_workflows // [])[]' <<<"$pub")
  if (( ${#signers[@]} == 0 )); then
    out=$(gh_retry attestation verify "oci://${src}@${d}" --repo "$repo" --format json) || return 1
  else
    for s in "${signers[@]}"; do
      out=$(gh_retry attestation verify "oci://${src}@${d}" --repo "$repo" --signer-workflow "$s" --format json) && break
      out=""
    done
    [[ -n $out ]] || return 1
  fi
  certs=$(jq -c --argjson p "$pub" '[.[].verificationResult.signature.certificate
    | select(.sourceRepositoryRef | test($p.source_refs))
    | select(.runnerEnvironment == "github-hosted" or ($p.allow_self_hosted // false))]' <<<"$out")
  [[ $(jq length <<<"$certs") -gt 0 ]] || return 1

  if jq -e '(.actors // []) | length > 0' <<<"$pub" >/dev/null; then
    local cert run actor
    while read -r cert; do
      run=$(jq -r '.runInvocationURI | capture("github.com/(?<r>[^/]+/[^/]+)/actions/runs/(?<id>[0-9]+)") | "\(.r)/actions/runs/\(.id)"' <<<"$cert")
      actor=$(gh_retry api "repos/${run}" --jq '.triggering_actor.login') || continue
      if jq -e --arg a "$actor" '.actors | index($a)' <<<"$pub" >/dev/null; then
        jq -c --arg a "$actor" '. + {actor: $a}' <<<"$cert"
        return 0
      fi
    done < <(jq -c '.[]' <<<"$certs")
    return 1
  fi
  jq -c '.[0]' <<<"$certs"
}

# One publisher must authorise the whole request: all tags and all digests.
authorised=""
while read -r pub; do
  tag_re=$(jq -r 'if (.tags // "") == "" then ".*" else .tags end' <<<"$pub")
  ok=1
  for t in "${tags[@]}"; do [[ $t =~ $tag_re ]] || { ok=""; break; }; done
  [[ -n $ok ]] || continue
  lines=()
  for d in "${!seen[@]}"; do
    cert=$(authorise "$pub" "$d") || { ok=""; break; }
    lines+=("verified ${d:0:19}: $(jq -r '"\(.sourceRepositoryURI | sub("^https://github.com/"; "")) \(.sourceRepositoryRef) \(.runnerEnvironment) \(.buildSignerURI | sub("^https://github.com/"; "") | sub("@.*"; ""))\(if .actor then " actor=" + .actor else "" end)"' <<<"$cert")")
  done
  if [[ -n $ok ]]; then
    authorised=1
    printf '%s\n' "${lines[@]}"
    break
  fi
done < <(jq -c '.[]' <<<"$RULE")
[[ -n $authorised ]] || fail "no publisher of ${IMAGE} has attestations covering this request"

for i in "${!tags[@]}"; do
  target="${dest}:${tags[$i]}"
  if [[ $(regctl image digest "$target" 2>/dev/null || true) == "${digests[$i]}" ]]; then
    result="already current"
  else
    regctl image copy --digest-tags --referrers "${src}@${digests[$i]}" "$target" >/dev/null
    [[ $(regctl image digest "$target") == "${digests[$i]}" ]] || fail "digest mismatch after copying ${target}"
    result="copied"
  fi
  echo "${target} -> ${digests[$i]:0:19} (${result})"
done
