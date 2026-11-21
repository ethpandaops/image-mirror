# image-mirror

Copies container images built by GitHub Actions from one registry to another,
after checking each image's [GitHub artifact attestations] against an
allowlist.

It lets many repositories publish to a destination registry (for example
Docker Hub) without any of them holding the destination's credentials. Each
repository pushes to a source registry it already has access to (for example
GHCR with its own `GITHUB_TOKEN`), attests what it pushed, and asks
image-mirror to copy it. Only image-mirror holds the destination credential.

## How it works

1. A workflow builds and pushes `<source>/<image>:<tag>`, then creates a
   build provenance attestation for every manifest digest it pushed.
2. image-mirror receives a request to mirror `tag@digest` pairs for that image,
   either from the workflow itself or from its own poller.
3. For every manifest behind every requested tag (the index and each
   platform manifest), it verifies the attestation with `gh attestation verify`
   and checks it against the image's allowlist entry.
4. If everything checks out, it copies the image by digest with
   `regctl image copy` and confirms the destination digest matches. Only the
   image is copied: referrers and `sha256-*` digest tags are not, because
   anyone who can push to the source can attach them and nothing attests
   them.

A request is refused unless:

- the image is in the allowlist;
- one of the image's publishers has attested every digest, from an allowed
  ref, on a GitHub-hosted runner (unless that publisher allows self-hosted
  runners), and, when configured, from the repository with the configured
  ID, an allowed workflow and an allowed actor;
- every tag matches the publisher's tag pattern;
- each source tag currently points at the requested digest;
- the destination repository already exists. image-mirror never creates
  repositories.

## Triggering a mirror

### From a workflow

`POST /v1/mirror` with the job's GitHub OIDC token as a bearer token, using
the audience configured with `-audience`:

```json
{
  "image": "my-image",
  "tags": ["v1.2.3@sha256:…", "latest@sha256:…"]
}
```

| Status | Meaning |
| --- | --- |
| `200` | Mirrored. The body lists what was verified and copied. |
| `202` | Still running. The body is a job ID; poll `GET /v1/jobs/{id}` with a fresh token from the same repository. |
| `401` | Missing or invalid token. |
| `403` | The calling repository, ref or runner may not publish this image. |
| `422` | Verification or copy failed. The body says why. |
| `429` | The calling repository already has `-max-jobs-per-repo` jobs queued or running, or the service has `-max-jobs`. Retry later. |

The caller's token is checked first so bad requests fail fast, but the
attestations are what authorise a copy. Copies run detached from the request,
so a dropped connection doesn't abort one.

A workflow step looks like this, after the image has been pushed and attested:

```yaml
permissions:
  id-token: write

steps:
  - name: Mirror
    env:
      MIRROR_URL: https://mirror.example.com
    run: |
      token=$(curl -fsS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=image-mirror" | jq -r .value)
      echo "::add-mask::$token"
      printf 'Authorization: Bearer %s\n' "$token" | curl -fsS -H @- \
        -H 'Content-Type: application/json' \
        --data '{"image":"my-image","tags":["v1.2.3@sha256:…"]}' \
        "$MIRROR_URL/v1/mirror"
```

### Poller

Every `-poll-interval`, image-mirror lists the source tags of each allowlisted
image and mirrors any the destination doesn't have yet. This catches requests
that were missed and images whose workflows never call the endpoint. It never
moves a tag that already exists at the destination: moving tags such as
`latest` only change through a request from a publishing job. It verifies at
most `-poll-max-per-image` tags per image per cycle, so a flood of tags in one source
package cannot starve the others. A digest that fails verification is logged
and retried after an hour.

## Configuration

### Allowlist

```yaml
# Images are copied from <source>/<image> to <destination>/<image>.
source: ghcr.io/example
destination: docker.io/example

defaults:
  source_refs: '.*'          # regex on the attested git ref
  allow_self_hosted: false   # accept attestations from self-hosted runners

images:
  # Every image has the same shape: a list of publishers, each the
  # repository that may publish it and the conditions it must meet.
  my-image:
    publishers:
      - repo: example/my-repo

  shared-image:
    publishers:
      - repo: example/my-repo
      - repo: example/builder
        tags: 'nightly-.*'

  release-image:
    publishers:
      - repo: example/release-repo
        repo_id: 123456789       # gh api repos/example/release-repo --jq .id
        source_refs: 'refs/tags/v[0-9]+\.[0-9]+\.[0-9]+'
        signer_workflows:
          - example/release-repo/.github/workflows/release.yaml
        actors: [alice, bob]     # who triggered the attested run
        tags: 'v[0-9.]+|latest'
```

Set `poll: false` on an image to keep the poller away from it. The poller reads
the digest of every allowed source tag of every image each cycle, so an image
that gains a tag per commit makes every cycle slower; with `poll: false` its
tags only reach the destination through publish requests.

A request is allowed when one publisher allows all of it. Unknown fields are
an error, so a misspelt restriction can't be silently ignored. Regexes must
match the whole ref or tag: `refs/heads/main` does not allow
`refs/heads/main-old`, and `nightly-` allows only the tag `nightly-`. Write
them in the common subset of Go RE2 and jq (Oniguruma) syntax, which both
the service and the verify script evaluate.

| Publisher field | Meaning |
| --- | --- |
| `repo` | `owner/name` of the repository whose attestations count. |
| `repo_id` | Numeric ID of `repo`. When set, attestations and callers must come from the repository with this ID as well as this name, so a repository deleted or renamed and then recreated under the same name, or an owner name taken over, cannot publish. Recommended. |
| `source_refs` | Regex the whole attested ref must match. Defaults to `defaults.source_refs`. |
| `signer_workflows` | Workflow files (`owner/repo/.github/workflows/file`) allowed to have signed the attestation, matched exactly. Any workflow in `repo` when unset. |
| `actors` | GitHub logins allowed to have triggered the attested run. Both the user who started the run and the user who started the attested attempt must be listed. Any when unset. |
| `events` | Events allowed to have triggered the attested run (`push`, `workflow_dispatch`, `pull_request_target`, ...). Any when unset. A `pull_request_target` run builds pull request code but attests as the base branch, so give it its own publisher entry limited to tags such as `pr-[0-9]+`. |
| `tags` | Regex every whole requested tag must match. Any when unset. |
| `exclude_tags` | Regex no whole requested tag may match, for rules a lookahead-free regex can't express, such as any tag except `latest`. None when unset. |
| `allow_self_hosted` | Accept attestations made on self-hosted runners. Anyone who controls a runner that can pick up `repo`'s jobs can then publish the image. |

`actors` is checked by looking up the attested run attempt, so pair it with a
rule on who can push the refs in `source_refs` (for example a tag ruleset).
Logins can be renamed and reused; `actors` trusts whoever holds the login when
the run is looked up.

### What an attestation does and does not prove

An attestation binds a digest to the repository, ref, workflow and runner that
signed it. It does not bind a tag. Anyone who can push to the source package
can point an allowed tag at any digest the publisher ever attested from an
allowed ref. The poller only creates missing tags, so this can't move an
existing destination tag on its own, but a new tag can still be created
pointing at any such digest, and a publish request can be replayed with a
token from the publishing repository. Restrict who can write to the source
packages, and use `tags` and `source_refs` to keep release tags and branch
builds apart.

The attestation is also only as good as the job that made it: it says that
job vouched for the digest, not that it built it. A job that attests what a
tag points to after another job pushed it (for example a merge job in a
split build) vouches for that other job's output.

### Flags

| Flag | Default | |
| --- | --- | --- |
| `-config` | `images.yaml` | Allowlist file. |
| `-listen` | `:8080` | HTTP listen address. |
| `-audience` | `image-mirror` | Required OIDC audience. |
| `-poll-interval` | `2m` | Poller interval; `0` disables it. |
| `-poll-max-per-image` | `10` | Tags the poller verifies per image per cycle; the rest wait for later cycles. |
| `-max-jobs-per-repo` | `4` | Mirror jobs a calling repository may have queued or running. |
| `-max-jobs` | `32` | Mirror jobs queued or running in total. |
| `-script` | `scripts/mirror.sh` | Verify-and-copy script. |

### Environment

| Variable | |
| --- | --- |
| `GITHUB_APP_ID`, `GITHUB_APP_INSTALLATION_ID`, `GITHUB_APP_PRIVATE_KEY_FILE` | A GitHub App used for the attestations API and run lookups. The service mints installation tokens scoped to read-only `attestations`, `actions` and `metadata`, refreshes them so each lasts longer than a verify-and-copy run, and passes subprocesses only the token in their environment (they run as the same user, so they can still read the key file). The App needs those three read permissions and an installation on the repositories that publish images. |
| `GH_TOKEN` | Instead of a GitHub App: a static read-only GitHub token. |
| `DESTINATION_USERNAME`, `DESTINATION_TOKEN` | Push credential for the destination registry. |
| `SOURCE_USERNAME`, `SOURCE_TOKEN` | Optional, to read private source images. |

Credentials are passed to `regctl` on stdin, never as arguments.

## Running

Images are published to `ghcr.io/ethpandaops/image-mirror` for `linux/amd64`
and `linux/arm64`, tagged `latest` and with the full commit SHA of every
commit on `main`. Pin a commit SHA or digest in production.

```sh
docker run --rm -p 8080:8080 \
  -v "$PWD/images.yaml:/config/images.yaml:ro" \
  -v "$PWD/app.pem:/secrets/app.pem:ro" \
  -e GITHUB_APP_ID -e GITHUB_APP_INSTALLATION_ID -e GITHUB_APP_PRIVATE_KEY_FILE=/secrets/app.pem \
  -e DESTINATION_USERNAME -e DESTINATION_TOKEN \
  ghcr.io/ethpandaops/image-mirror:latest \
  -config /config/images.yaml
```

Each image has a build provenance attestation:

```sh
gh attestation verify oci://ghcr.io/ethpandaops/image-mirror@sha256:… --repo ethpandaops/image-mirror
```

The container runs as UID 10001, includes pinned, checksummed `gh`, `regctl`
and `jq`, and serves `GET /healthz`. It needs a writable home directory and
`/tmp` (`regctl` keeps its registry logins in `~/.regctl`). It serves plain
HTTP: put it behind a proxy that terminates TLS. To build it yourself:

```sh
docker build -t image-mirror .
```

On Kubernetes, mount the allowlist from a ConfigMap, the App key as a file and
the destination credential from a Secret, and point a liveness probe at `/healthz`. Run one replica: jobs and the
poller's state live in memory, and two replicas would poll and copy the same
tags.

## Development

```sh
go test ./...          # needs bash and jq: it runs scripts/mirror.sh against fake gh and regctl
shellcheck scripts/mirror.sh
```

[GitHub artifact attestations]: https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations
