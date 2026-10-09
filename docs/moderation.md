# Moderation intake

Signed-in viewers report a creator or a recording. Each report is stored once,
moderators are notified, and a moderator's response and any action are
recorded with the response time. This is
[arkavo-rs#77](https://github.com/arkavo-org/arkavo-rs/issues/77), for App Store
Review Guideline 1.2: "a mechanism to report offensive content and timely
responses to concerns". The viewer side is arkavo-ios ADR-0040 and ADR-0043
(`specs/moderation.spec.yaml`, ARK-280..ARK-294).

The intake is off unless `MODERATION_INTAKE=on`. When it is off, every route
below returns 404.

## Decisions

| Question in #77 | Decision |
|---|---|
| Transport | HTTPS, `POST https://platform.arkavo.net/moderation/v1/reports`. Not `/ws`: a report is one request with a JSON reply, and `/ws` has no per-request status code. |
| Signed-out reporters | Refused (401). The product owner decided on 2026-10-02 that reporting requires sign-in (ADR-0043). |
| Credential | `Authorization: Bearer <session CWT>`, the `identity.arkavo.net` passkey auth token that the app already sends to the KAS. It must carry `aud` `arkavo`. Service-account, `client:` and OIDC access tokens (those with `scope` or `auth_time`) are refused, and so is any token with an agent marker (`arkavo_npe`, `arkavo_swarm`, `arkavo_state_version` or the `agent` role). |
| Reporter identity | Taken only from the token's `sub` and stored with the report. The payload has no reporter field, and unknown keys are refused. |
| One record per report | Keyed by the report ID with a conditional put. A second report about the same recording is a new record. A resubmission of the same ID by the same account with the same content returns 200 with the original receipt, before any rate limit is applied. Any other reuse of an ID returns 409. |
| Abuse limits | 10 reports per account per hour and 50 per day, counted in Redis. Over a limit returns 429 with `Retry-After`. Only new reports are counted: a retry of a stored report, or a request that fails because the store is down, uses no quota. If Redis is unreachable, the report is accepted, because losing a report is worse than accepting one more. The body is capped at 64 KiB, which holds any note the viewer accepts. |
| Retention | 365 days after the report is resolved (`MODERATION_RETENTION_DAYS`), enforced by DynamoDB TTL on `expires_at`. An open report never expires. |
| Notification | NATS `moderation.reports.received`. The alert names the report and its target and carries neither the note nor the reporter. |
| Actions | Takedown and suspend are published to NATS as `moderation.actions.takedown` and `moderation.actions.suspend` for the enforcing services (tdf-iroh-s3#17, authnz-rs#91). They are sent before the report is stored as actioned; if they cannot be delivered, the PATCH returns 503 and the report is unchanged. |

## Report payload (frozen contract)

These are the keys of the viewer's `ModerationReport.jsonPayload()` plus
`appVersion` and `note`. Any other key is refused.

```json
{
  "id": "6F9619FF-8B86-D011-B42D-00C04FC964FF",
  "reasons": ["harassment"],
  "blockUser": true,
  "timestamp": "2026-10-02T12:00:00Z",
  "contentId": "content-1",
  "blockedPublicID": "creator-subject",
  "appVersion": "App: Arkavo 3.0 (112)",
  "note": "optional, up to 1000 characters"
}
```

| Key | Rule |
|---|---|
| `id` | A UUID in any case. It is stored lowercase. |
| `reasons` | Non-empty, no duplicates, each one of `spam`, `harassment`, `hateSpeech`, `violence`, `adultContent`, `copyright`, `privacy`, `misinformation`, `other`. |
| `blockUser` | Whether the creator is blocked on the reporter's device. |
| `timestamp` | RFC 3339; the time the viewer built the report. The server's receive time is the authoritative one. |
| `contentId`, `blockedPublicID` | Optional, and `null` means absent. When present: 1–256 bytes, with no whitespace or control characters. Both are `null` for a recording imported from Files that has no valid asset ID. |
| `appVersion` | Optional, up to 128 characters. |
| `note` | Optional. It is normalised as on the device (ARK-280) and must be at most 1,000 extended grapheme clusters. A note that is empty after normalisation counts as no note. |

| Response | Meaning |
|---|---|
| `201 {"id","status":"received","receivedAt"}` | Stored, and moderators notified. |
| `200` (same body) | The same report was already stored for this account. |
| `400 {"error"}` | Invalid payload. |
| `401` | No valid person's session. |
| `409` | The report ID is already used by a different report. |
| `413` | Body over 64 KiB. |
| `429` + `Retry-After` | Over the account's limit. |
| `503` | Store or key set unavailable. Not stored; the viewer shows Failed. |

## Moderators

A moderator is a person whose account ID is listed in `MODERATION_MODERATORS`.
They authenticate with their own session CWT, the same way a reporter does.

- `GET /moderation/v1/reports?status=received&limit=50&cursor=…` lists a status
  queue, oldest first. `limit` is at most 100. Pass `nextCursor` as `cursor` to
  get the next page.
- `GET /moderation/v1/reports/{id}` returns the full record, including the note
  and the reporter.
- `PATCH /moderation/v1/reports/{id}` with `{"status": "...", "actions": [...], "note": "..."}`.

Status moves `received → reviewing → actioned | dismissed`. A report can also go
from `received` straight to `actioned` or `dismissed`. `actioned` and
`dismissed` are final (409).

- `actioned` needs at least one action. `takedown` needs a reported `contentId`,
  and `suspend` needs a reported creator. Other statuses take no actions.
- The first change out of `received` records `firstResponseAt` and
  `responseSeconds`. This is the response-time measure for the committed
  response time ("Arkavo reviews reports within 24 hours").
- A final status records `resolvedAt`, `moderatorSubject` and the optional
  `resolutionNote`.
- A concurrent change returns 409. Read the report again and retry.
- `actioned` publishes its action events first and stores the status only if
  every event reached NATS. Otherwise the PATCH returns 503 and the report is
  unchanged, so the moderator can retry. A retry after a partial failure
  sends an action again, so the enforcing services must treat actions as
  idempotent (keyed by `reportId` and `action`).

```sh
curl -s -H "Authorization: Bearer $CWT" \
  https://platform.arkavo.net/moderation/v1/reports?status=received
curl -s -X PATCH -H "Authorization: Bearer $CWT" -H 'content-type: application/json' \
  -d '{"status":"actioned","actions":["takedown"],"note":"violates content standard"}' \
  https://platform.arkavo.net/moderation/v1/reports/<id>
```

## NATS events

| Subject | When | Body |
|---|---|---|
| `moderation.reports.received` | A new report is stored | `type`, `id`, `reasons`, `creatorSubject`, `contentId`, `receivedAt` |
| `moderation.actions.takedown` | A report is actioned with `takedown` | `type`, `action`, `reportId`, `creatorSubject`, `contentId`, `moderator`, `at` |
| `moderation.actions.suspend` | A report is actioned with `suspend` | same |

`MODERATION_NATS_PREFIX` changes the `moderation` prefix. Each publish is
flushed to the NATS server within 2 seconds.

- `reports.received` is best effort. The report is stored first, so the queue
  (`GET … ?status=received`) is the backstop when NATS is down.
- The action subjects are the hand-off to the enforcing services. A successful
  publish means the NATS server has the event, not that a subscriber took it:
  core NATS keeps nothing for a subscriber that is down. Until the enforcing
  services subscribe, a moderator must also carry out the takedown or
  suspension by hand.

## Storage

The table is DynamoDB `prod-moderation-reports` in `us-east-1`.

| Attribute | Use |
|---|---|
| `report_id` (S, hash key) | Report ID |
| `status` (S), `received_at` (N) | GSI `status-received_at-index` (projection ALL), the moderator queue |
| `expires_at` (N) | TTL (retention); written only when the report is resolved |
| `record` (S) | The full record as JSON |

### On this server: DynamoDB Local

Production on the Arkavo server runs the table in a DynamoDB Local container, not in AWS. arks then needs no AWS credentials for moderation. `MODERATION_DYNAMODB_ENDPOINT` points only the moderation client at the container, with fixed placeholder credentials, so the S3 client's AWS credentials are not affected.

```sh
docker volume create arks-dynamodb-data
# DynamoDB Local runs as uid 1000; a fresh named volume is root-owned.
docker run --rm -v arks-dynamodb-data:/d alpine chown 1000:1000 /d
docker run -d --name arks-dynamodb --restart unless-stopped \
    -p 127.0.0.1:8000:8000 -v arks-dynamodb-data:/home/dynamodblocal/data \
    -w /home/dynamodblocal amazon/dynamodb-local \
    -jar DynamoDBLocal.jar -sharedDb -dbPath ./data

# The container listens on 127.0.0.1 only. Reach it from the CLI through its
# network namespace.
alias ddb='docker run --rm --network container:arks-dynamodb \
    -e AWS_ACCESS_KEY_ID=local -e AWS_SECRET_ACCESS_KEY=local amazon/aws-cli \
    --endpoint-url http://127.0.0.1:8000 --region us-east-1'
ddb dynamodb create-table --table-name prod-moderation-reports \
    --attribute-definitions AttributeName=report_id,AttributeType=S \
        AttributeName=status,AttributeType=S AttributeName=received_at,AttributeType=N \
    --key-schema AttributeName=report_id,KeyType=HASH \
    --global-secondary-indexes 'IndexName=status-received_at-index,KeySchema=[{AttributeName=status,KeyType=HASH},{AttributeName=received_at,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
    --billing-mode PAY_PER_REQUEST
ddb dynamodb update-time-to-live --table-name prod-moderation-reports \
    --time-to-live-specification Enabled=true,AttributeName=expires_at
```

What DynamoDB Local does not give you:

- **Backups.** There is no point-in-time recovery. The data is one SQLite file in the `arks-dynamodb-data` volume. Back it up, for example nightly with `docker run --rm -v arks-dynamodb-data:/d -v "$PWD":/b alpine tar czf /b/arks-dynamodb-$(date +%F).tgz -C /d .`. These records are the evidence of timely responses.
- **Availability while Docker is down.** The container restarts with Docker, so Docker Desktop must start at login. While it is down, intake returns 503.
- **A service AWS supports for production use.** AWS supports DynamoDB Local for development only. To move to AWS later, use the next section and unset `MODERATION_DYNAMODB_ENDPOINT`.

### Create the table (AWS)

Production tables are created with the CLI, as in authnz-rs
`docs/app-attest-gate-deployment.md`; nothing in `devsecops` provisions this
one.

```sh
aws dynamodb create-table \
    --region us-east-1 \
    --table-name prod-moderation-reports \
    --attribute-definitions \
        AttributeName=report_id,AttributeType=S \
        AttributeName=status,AttributeType=S \
        AttributeName=received_at,AttributeType=N \
    --key-schema AttributeName=report_id,KeyType=HASH \
    --global-secondary-indexes \
        'IndexName=status-received_at-index,KeySchema=[{AttributeName=status,KeyType=HASH},{AttributeName=received_at,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
    --billing-mode PAY_PER_REQUEST \
    --sse-specification Enabled=true
aws dynamodb wait table-exists --region us-east-1 --table-name prod-moderation-reports

# Retention.
aws dynamodb update-time-to-live --region us-east-1 \
    --table-name prod-moderation-reports \
    --time-to-live-specification Enabled=true,AttributeName=expires_at

# Point-in-time recovery is off by default. These records are the evidence of
# timely responses, so turn it on.
aws dynamodb update-continuous-backups --region us-east-1 \
    --table-name prod-moderation-reports \
    --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true
```

### Credentials

The arks host needs `dynamodb:PutItem`, `GetItem` and `Query` on the table and
its index:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Query"],
    "Resource": [
      "arn:aws:dynamodb:us-east-1:<account-id>:table/prod-moderation-reports",
      "arn:aws:dynamodb:us-east-1:<account-id>:table/prod-moderation-reports/index/*"
    ]
  }]
}
```

arks uses the default AWS credential chain, as the S3 client does. It runs
under `sudo start.sh`, so check which credentials that chain finds there
(`sudo sh -c 'echo $HOME'`), and prefer a dedicated IAM user's keys exported in
`production/start.sh` over SSO credentials, which expire.

## Configuration

```sh
MODERATION_INTAKE=on                              # off (default) | on
MODERATION_REPORTS_TABLE=prod-moderation-reports  # required when on
MODERATION_STATUS_INDEX=status-received_at-index  # default shown
MODERATION_MODERATORS=<account-uuid>,<account-uuid>  # who may read and respond; `arkavo:` prefix optional
MODERATION_EXPECTED_AUD=arkavo                    # default shown
MODERATION_COSE_KEYS_URL=…                        # default ${OIDC_ISSUER}/.well-known/cose-keys
OIDC_ISSUER=https://identity.arkavo.net           # default shown; shared with the AuthZEN facade
MODERATION_RETENTION_DAYS=365
MODERATION_RATE_LIMIT_HOURLY=10                   # 0 disables
MODERATION_RATE_LIMIT_DAILY=50                    # 0 disables
MODERATION_NATS_PREFIX=moderation
AWS_REGION=us-east-1                              # for DynamoDB, if not already set
MODERATION_DYNAMODB_ENDPOINT=http://127.0.0.1:8000 # optional: DynamoDB Local instead of AWS
```

## Privacy

Each stored report holds:

- the reporter's account ID;
- the reported creator and recording;
- the reasons and the optional note;
- whether the reporter blocked the creator;
- the app version and the two timestamps.

It holds no IP address, device identifier or token. Rate-limit counters hold
the account ID in Redis for at most a day. Records are deleted 365 days after
resolution, and an open report is kept until it is resolved. The App Privacy
label (arkavo-ios ARK-388) and the privacy policy
should describe this data.
