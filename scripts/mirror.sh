#!/usr/bin/env bash
# Verifies a mirror request and copies <SOURCE>/<IMAGE> to <DESTINATION>/<IMAGE>.
# RULE is the image's publishers as JSON, with source_refs and tags anchored.
# IMAGE and TAGS (tag@sha256:digest pairs) are untrusted, and so is everything
# in the source registry until an attestation covers it. Credentials reach
# tools via stdin.
set -euo pipefail

fail() { echo "error: $*"; exit 1; }

max_manifests=64 # per request, across all tags
max_depth=2      # index -> index -> manifest

[[ $IMAGE =~ ^[a-z0-9][a-z0-9._-]{0,127}$ ]] || fail "invalid image name"
[[ $REQUEST_ID =~ ^[A-Za-z0-9._-]{1,64}$ ]] || fail "invalid request_id"
[[ -n ${RULE:-} && -n ${SOURCE:-} && -n ${DESTINATION:-} ]] || fail "RULE, SOURCE and DESTINATION are required"
jq -e 'type == "array" and length > 0' <<<"$RULE" >/dev/null || fail "invalid RULE"
src="${SOURCE}/${IMAGE}"
dest="${DESTINATION}/${IMAGE}"

read -ra pairs <<<"${TAGS:-}"
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
# Nothing below needs the registry credentials in its environment.
unset SOURCE_TOKEN DESTINATION_TOKEN

regctl tag ls --limit 1 "$dest" >/dev/null 2>&1 || fail "${dest} does not exist"

# Every manifest behind every tag (index and per-platform manifests). This runs
# before anything is verified, on content anyone who can push to the source
# can shape, so it is bounded.
declare -A seen=()
tree() {
  local d=$1 depth=$2 body child
  [[ -n ${seen[$d]:-} ]] && return 0
  (( ${#seen[@]} < max_manifests )) || fail "more than ${max_manifests} manifests behind the requested tags"
  (( depth <= max_depth )) || fail "image index nested more than ${max_depth} deep"
  seen[$d]=1
  body=$(regctl manifest get "${src}@${d}" --format raw-body) || fail "cannot read ${src}@${d}"
  while read -r child; do
    [[ -n $child ]] || continue
    [[ $child =~ ^sha256:[a-f0-9]{64}$ ]] || fail "unsupported digest in ${d}"
    tree "$child" $((depth + 1))
  done < <(jq -r '(.manifests // [])[]
    | select((.annotations["vnd.docker.reference.type"] // "") != "attestation-manifest")
    | .digest' <<<"$body")
}

for i in "${!tags[@]}"; do
  current=$(regctl image digest "${src}:${tags[$i]}") || fail "${src}:${tags[$i]} not found"
  [[ $current == "${digests[$i]}" ]] || fail "${src}:${tags[$i]} is ${current}, not ${digests[$i]}"
  tree "${digests[$i]}" 0
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

# The publisher's rules, applied to each signed certificate gh verified. gh
# checks the signature, the predicate type and the source repository; its
# signer workflow check only matches a prefix, so the signer is checked here,
# exactly, together with everything else.
# shellcheck disable=SC2016
policy='
def allowed($p):
  . as $c
  | ("https://github.com/" + $p.repo | ascii_downcase) as $repo
  | ($c.sourceRepositoryURI | ascii_downcase) == $repo
    and ($p.repo_id == null or $c.sourceRepositoryIdentifier == ($p.repo_id | tostring))
    and ($c.sourceRepositoryRef | test($p.source_refs))
    and ($c.runnerEnvironment == "github-hosted" or $p.allow_self_hosted == true)
    and (if ($p.signer_workflows // []) == []
      then $c.subjectAlternativeName | ascii_downcase | startswith($repo + "/")
      else any($p.signer_workflows[]; . as $w
        | $c.subjectAlternativeName | startswith("https://github.com/" + $w + "@"))
      end);
[.[].verificationResult.signature.certificate | select(allowed($p))]'

# Prints the certificate of an attestation for digest $2 that satisfies
# publisher $1, or fails.
authorise() {
  local pub=$1 d=$2 repo out certs cert run who
  repo=$(jq -r .repo <<<"$pub")
  out=$(gh_retry attestation verify "oci://${src}@${d}" --repo "$repo" \
    --cert-identity-regex '^https://github\.com/' --format json) || return 1
  certs=$(jq -c --argjson p "$pub" "$policy" <<<"$out") || return 1
  [[ $(jq length <<<"$certs") -gt 0 ]] || return 1

  if ! jq -e '(.actors // []) | length > 0' <<<"$pub" >/dev/null; then
    jq -c '.[0]' <<<"$certs"
    return 0
  fi
  # Who started the attested run and who started this attempt of it must
  # both be allowed. The attempt is looked up, not the run, whose latest
  # attempt may have been started by someone else.
  while read -r cert; do
    run=$(jq -r '.runInvocationURI
      | capture("^https://github\\.com/(?<r>[^/]+/[^/]+)/actions/runs/(?<id>[0-9]+)/attempts/(?<n>[0-9]+)$")
      | "repos/\(.r)/actions/runs/\(.id)/attempts/\(.n)"' <<<"$cert") || continue
    [[ -n $run ]] || continue
    who=$(gh_retry api "$run" --jq '{actor: .actor.login, triggering_actor: .triggering_actor.login}') || continue
    if jq -e --argjson p "$pub" '[.actor, .triggering_actor] | all(. as $a | any($p.actors[]; . == $a))' <<<"$who" >/dev/null; then
      jq -c --argjson w "$who" '. + {actor: $w.triggering_actor}' <<<"$cert"
      return 0
    fi
  done < <(jq -c '.[]' <<<"$certs")
  return 1
}

# One publisher must authorise the whole request: all tags and all digests.
authorised=""
while read -r pub; do
  jq -n -e --argjson p "$pub" '($p.tags // "") as $re | $re == "" or ($ARGS.positional | all(test($re)))' \
    --args "${tags[@]}" >/dev/null 2>&1 || continue
  ok=1
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

# Only the attested image is copied. Referrers and sha256-* digest tags are
# not: anyone who can push to the source can attach them, and they are not
# covered by any attestation.
# FILL_ONLY (the poller) creates missing tags but never moves existing ones.
for i in "${!tags[@]}"; do
  target="${dest}:${tags[$i]}"
  existing=$(regctl image digest "$target" 2>/dev/null || true)
  if [[ $existing == "${digests[$i]}" ]]; then
    result="already current"
  elif [[ ${FILL_ONLY:-false} == true && -n $existing ]]; then
    result="left at ${existing:0:19}: existing tags only move through publish requests"
  else
    regctl image copy "${src}@${digests[$i]}" "$target" >/dev/null
    [[ $(regctl image digest "$target") == "${digests[$i]}" ]] || fail "digest mismatch after copying ${target}"
    result="copied"
  fi
  echo "${target} -> ${digests[$i]:0:19} (${result})"
done
