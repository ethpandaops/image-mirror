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
   `regctl image copy`, including referrers, and confirms the destination
   digest matches.

A request is refused unless:

- the image is in the allowlist;
- one of the image's publishers has attested every digest, from an allowed
  ref, on a GitHub-hosted runner (unless that publisher allows self-hosted
  runners), and, when configured, from an allowed workflow and actor;
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
image and mirrors any whose destination digest differs. This catches requests
that were missed and images whose workflows never call the endpoint. A digest
that fails verification is logged and not retried until restart.

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
        tags: '^nightly-'

  release-image:
    publishers:
      - repo: example/release-repo
        source_refs: '^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
        signer_workflows:
          - example/release-repo/.github/workflows/release.yaml
        actors: [alice, bob]     # who triggered the attested run
        tags: '^(v[0-9.]+|latest)$'
```

A request is allowed when one publisher allows all of it. Unknown fields are
an error, so a misspelt restriction can't be silently ignored.

| Publisher field | Meaning |
| --- | --- |
| `repo` | `owner/name` of the repository whose attestations count. |
| `source_refs` | Regex the attested ref must match. Defaults to `defaults.source_refs`. |
| `signer_workflows` | Workflow files (`owner/repo/path`) allowed to have signed the attestation. Any workflow in `repo` when unset. |
| `actors` | GitHub users allowed to have triggered the attested run. Any when unset. |
| `tags` | Regex every requested tag must match. Any when unset. |
| `allow_self_hosted` | Accept attestations made on self-hosted runners. Anyone who controls a runner that can pick up `repo`'s jobs can then publish the image. |

`actors` is checked by looking up the attested run, so pair it with a rule on
who can push the refs in `source_refs` (for example a tag ruleset).

### Flags

| Flag | Default | |
| --- | --- | --- |
| `-config` | `images.yaml` | Allowlist file. |
| `-listen` | `:8080` | HTTP listen address. |
| `-audience` | `image-mirror` | Required OIDC audience. |
| `-poll-interval` | `2m` | Poller interval; `0` disables it. |
| `-script` | `scripts/mirror.sh` | Verify-and-copy script. |

### Environment

| Variable | |
| --- | --- |
| `GITHUB_APP_ID`, `GITHUB_APP_INSTALLATION_ID`, `GITHUB_APP_PRIVATE_KEY_FILE` | A GitHub App used for the attestations API and run lookups. The service mints installation tokens scoped to read-only `attestations`, `actions` and `metadata`, refreshes them before they expire, and hands only the token to its subprocesses. The App needs those three read permissions and an installation on the repositories that publish images. |
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

The container runs as an unprivileged user, includes `gh`, `regctl` and `jq`,
and serves `GET /healthz`. To build it yourself:

```sh
docker build -t image-mirror .
```

On Kubernetes, mount the allowlist from a ConfigMap, the App key as a file and
the destination credential from a Secret, and point a liveness probe at `/healthz`. Run one replica: jobs and the
poller's state live in memory, and two replicas would poll and copy the same
tags.

## Development

```sh
go test ./...
bash -n scripts/mirror.sh
```

[GitHub artifact attestations]: https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations
