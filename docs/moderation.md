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
| One record per report | Keyed by the report ID with a conditional put. A second report about the same recording is a new record. A resubmission of the same ID by the same account with the same content returns 200 with the original receipt. Any other reuse of an ID returns 409. |
| Abuse limits | 10 reports per account per hour and 50 per day, counted in Redis. Over a limit returns 429 with `Retry-After`. If Redis is unreachable, the report is accepted, because losing a report is worse than accepting one more. The body is capped at 16 KiB. |
| Retention | 365 days from receipt (`MODERATION_RETENTION_DAYS`), enforced by DynamoDB TTL on `expires_at`. |
| Notification | NATS `moderation.reports.received`. The alert names the report and its target and carries neither the note nor the reporter. |
| Actions | Takedown and suspend are published to NATS as `moderation.actions.takedown` and `moderation.actions.suspend` for the enforcing services (tdf-iroh-s3#17, authnz-rs#91). |

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
| `413` | Body over 16 KiB. |
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

`MODERATION_NATS_PREFIX` changes the `moderation` prefix. Publishing is best
effort with a 2-second bound. The report is stored first, so the queue
(`GET … ?status=received`) is the backstop when NATS is down. The action
subjects are the hand-off to the enforcing services. Until they subscribe, a
moderator must also carry out the takedown or suspension by hand.

## Storage

The table is DynamoDB `prod-moderation-reports`. It is defined in
`arkavo-org/devsecops` `lambdas/template.yaml` (`ModerationReportsTable`).

| Attribute | Use |
|---|---|
| `report_id` (S, hash key) | Report ID |
| `status` (S), `received_at` (N) | GSI `status-received_at-index` (projection ALL), the moderator queue |
| `expires_at` (N) | TTL (retention) |
| `record` (S) | The full record as JSON |

The arks host needs `dynamodb:PutItem`, `GetItem` and `Query` on the table and
its index. It uses the default AWS credential chain, as the S3 client does.

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
receipt. The App Privacy label (arkavo-ios ARK-388) and the privacy policy
should describe this data.
