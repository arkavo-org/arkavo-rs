//! Report payload (the contract frozen with the iOS viewer), its validation,
//! and the stored record with its moderation status.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use unicode_segmentation::UnicodeSegmentation;
use uuid::Uuid;

/// Note bound, in extended grapheme clusters (the viewer's ARK-280 bound).
pub const NOTE_LIMIT: usize = 1_000;
/// Bound for a creator subject or a content ID.
pub const MAX_IDENTIFIER_LEN: usize = 256;
pub const MAX_APP_VERSION_LEN: usize = 128;
/// Bound for a moderator's resolution note.
pub const MAX_RESOLUTION_NOTE_LEN: usize = 2_000;

/// The nine reasons of the viewer's report sheet, with the viewer's raw values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Reason {
    Spam,
    Harassment,
    HateSpeech,
    Violence,
    AdultContent,
    Copyright,
    Privacy,
    Misinformation,
    Other,
}

impl Reason {
    fn parse(s: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Received,
    Reviewing,
    Actioned,
    Dismissed,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Received => "received",
            Status::Reviewing => "reviewing",
            Status::Actioned => "actioned",
            Status::Dismissed => "dismissed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "received" => Some(Status::Received),
            "reviewing" => Some(Status::Reviewing),
            "actioned" => Some(Status::Actioned),
            "dismissed" => Some(Status::Dismissed),
            _ => None,
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Status::Actioned | Status::Dismissed)
    }

    /// received → reviewing | actioned | dismissed; reviewing → actioned | dismissed.
    pub fn can_become(self, next: Status) -> bool {
        matches!(
            (self, next),
            (Status::Received, Status::Reviewing)
                | (
                    Status::Received | Status::Reviewing,
                    Status::Actioned | Status::Dismissed
                )
        )
    }
}

/// What a moderator did about an actioned report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Take the reported recording down (tdf-iroh-s3#17).
    Takedown,
    /// Suspend the reported creator (tdf-iroh-s3#17, authnz-rs#91).
    Suspend,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Takedown => "takedown",
            Action::Suspend => "suspend",
        }
    }
}

/// The request body. Key names are the viewer's `ModerationReport.jsonPayload()`
/// keys plus `appVersion` and `note`. Unknown keys are refused, so a client
/// cannot attach reporter identity to the payload.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportSubmission {
    pub id: String,
    pub reasons: Vec<String>,
    pub block_user: bool,
    pub timestamp: String,
    #[serde(default)]
    pub content_id: Option<String>,
    #[serde(default, rename = "blockedPublicID")]
    pub blocked_public_id: Option<String>,
    #[serde(default)]
    pub app_version: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidReport {
    pub id: Uuid,
    pub reasons: Vec<Reason>,
    pub blocked_on_device: bool,
    pub client_timestamp: DateTime<Utc>,
    pub content_id: Option<String>,
    pub creator_subject: Option<String>,
    pub app_version: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidReport(pub &'static str);

impl ReportSubmission {
    pub fn validate(self) -> Result<ValidReport, InvalidReport> {
        let id = Uuid::parse_str(&self.id).map_err(|_| InvalidReport("id must be a UUID"))?;
        if self.reasons.is_empty() {
            return Err(InvalidReport("reasons must not be empty"));
        }
        let mut reasons = Vec::with_capacity(self.reasons.len());
        for raw in &self.reasons {
            let reason = Reason::parse(raw).ok_or(InvalidReport("unknown reason"))?;
            if reasons.contains(&reason) {
                return Err(InvalidReport("duplicate reason"));
            }
            reasons.push(reason);
        }
        let client_timestamp = DateTime::parse_from_rfc3339(&self.timestamp)
            .map_err(|_| InvalidReport("timestamp must be RFC 3339"))?
            .with_timezone(&Utc);
        let content_id = identifier(self.content_id, "invalid contentId")?;
        let creator_subject = identifier(self.blocked_public_id, "invalid blockedPublicID")?;
        let app_version = match self.app_version {
            None => None,
            Some(v) => {
                let v = v.trim();
                if v.chars().count() > MAX_APP_VERSION_LEN || v.chars().any(char::is_control) {
                    return Err(InvalidReport("invalid appVersion"));
                }
                (!v.is_empty()).then(|| v.to_string())
            }
        };
        let note = match self.note {
            None => None,
            Some(raw) => {
                let note = normalised_note(&raw);
                if note.graphemes(true).count() > NOTE_LIMIT {
                    return Err(InvalidReport("note exceeds 1000 characters"));
                }
                (!note.is_empty()).then_some(note)
            }
        };
        Ok(ValidReport {
            id,
            reasons,
            blocked_on_device: self.block_user,
            client_timestamp,
            content_id,
            creator_subject,
            app_version,
            note,
        })
    }
}

/// Subjects and content IDs: null is absent; a present value must be non-empty,
/// bounded, and free of whitespace and control characters.
fn identifier(v: Option<String>, err: &'static str) -> Result<Option<String>, InvalidReport> {
    match v {
        None => Ok(None),
        Some(s) => {
            if s.is_empty()
                || s.len() > MAX_IDENTIFIER_LEN
                || s.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                Err(InvalidReport(err))
            } else {
                Ok(Some(s))
            }
        }
    }
}

/// The viewer's ARK-280 normalisation, repeated here so a stored note never
/// holds control characters whatever the client sent: line endings become
/// line feeds, other control characters go, and the ends are trimmed.
pub fn normalised_note(raw: &str) -> String {
    let lf = raw.replace("\r\n", "\n").replace('\r', "\n");
    let kept: String = lf
        .chars()
        .filter(|&c| c == '\n' || !c.is_control())
        .collect();
    kept.trim().to_string()
}

/// One stored report. `id` is the key: a later report about the same
/// recording is a new record, never an overwrite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportRecord {
    pub id: String,
    pub status: Status,
    pub reasons: Vec<Reason>,
    pub creator_subject: Option<String>,
    pub content_id: Option<String>,
    pub blocked_on_device: bool,
    pub app_version: Option<String>,
    pub note: Option<String>,
    /// When the viewer built the report, as the viewer sent it.
    pub client_timestamp: String,
    /// Unix seconds; the authoritative receive time.
    pub received_at: i64,
    /// The reporter's account, from the session token. Never from the payload.
    pub reporter_subject: String,
    /// When a moderator first moved the report out of `received`.
    pub first_response_at: Option<i64>,
    /// `first_response_at - received_at`, the measure of response time.
    pub response_seconds: Option<i64>,
    pub resolved_at: Option<i64>,
    pub actions: Vec<Action>,
    pub moderator_subject: Option<String>,
    pub resolution_note: Option<String>,
    /// Unix seconds; the store deletes the record after this (retention).
    pub expires_at: i64,
}

impl ReportRecord {
    pub fn new(
        report: ValidReport,
        reporter_subject: String,
        received_at: i64,
        retention_secs: i64,
    ) -> Self {
        Self {
            id: report.id.to_string(),
            status: Status::Received,
            reasons: report.reasons,
            creator_subject: report.creator_subject,
            content_id: report.content_id,
            blocked_on_device: report.blocked_on_device,
            app_version: report.app_version,
            note: report.note,
            client_timestamp: report.client_timestamp.to_rfc3339(),
            received_at,
            reporter_subject,
            first_response_at: None,
            response_seconds: None,
            resolved_at: None,
            actions: Vec::new(),
            moderator_subject: None,
            resolution_note: None,
            expires_at: received_at.saturating_add(retention_secs),
        }
    }

    /// Whether `other` is a resubmission of this report by the same reporter,
    /// i.e. a retry, and so safe to acknowledge again.
    pub fn same_submission(&self, other: &ReportRecord) -> bool {
        self.id == other.id
            && self.reporter_subject == other.reporter_subject
            && self.reasons == other.reasons
            && self.creator_subject == other.creator_subject
            && self.content_id == other.content_id
            && self.blocked_on_device == other.blocked_on_device
            && self.app_version == other.app_version
            && self.note == other.note
            && self.client_timestamp == other.client_timestamp
    }
}

/// A moderator's change to a report.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusUpdate {
    pub status: Status,
    #[serde(default)]
    pub actions: Vec<Action>,
    #[serde(default)]
    pub note: Option<String>,
}

impl StatusUpdate {
    /// Apply to `record` as `moderator` at `now`, or say why not.
    pub fn apply(
        self,
        record: &ReportRecord,
        moderator: &str,
        now: i64,
    ) -> Result<ReportRecord, InvalidReport> {
        if !record.status.can_become(self.status) {
            return Err(InvalidReport("status change not allowed"));
        }
        let mut actions = Vec::new();
        for a in self.actions {
            if actions.contains(&a) {
                return Err(InvalidReport("duplicate action"));
            }
            actions.push(a);
        }
        match self.status {
            Status::Actioned if actions.is_empty() => {
                return Err(InvalidReport("actioned requires at least one action"));
            }
            Status::Actioned => {
                if actions.contains(&Action::Takedown) && record.content_id.is_none() {
                    return Err(InvalidReport("takedown requires a reported content ID"));
                }
                if actions.contains(&Action::Suspend) && record.creator_subject.is_none() {
                    return Err(InvalidReport("suspend requires a reported creator"));
                }
            }
            _ if !actions.is_empty() => {
                return Err(InvalidReport("actions are only allowed with actioned"));
            }
            _ => {}
        }
        let note = match self.note {
            None => None,
            Some(n) => {
                let n = normalised_note(&n);
                if n.chars().count() > MAX_RESOLUTION_NOTE_LEN {
                    return Err(InvalidReport("note too long"));
                }
                (!n.is_empty()).then_some(n)
            }
        };
        let mut next = record.clone();
        next.status = self.status;
        if next.first_response_at.is_none() {
            next.first_response_at = Some(now);
            next.response_seconds = Some(now.saturating_sub(record.received_at).max(0));
        }
        if self.status.is_terminal() {
            next.resolved_at = Some(now);
        }
        next.actions = actions;
        next.moderator_subject = Some(moderator.to_string());
        if note.is_some() {
            next.resolution_note = note;
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn submission(v: serde_json::Value) -> Result<ValidReport, String> {
        serde_json::from_value::<ReportSubmission>(v)
            .map_err(|e| e.to_string())?
            .validate()
            .map_err(|e| e.0.to_string())
    }

    /// The bytes `ModerationReport.jsonPayload()` produces (sorted keys, ISO 8601).
    fn ios_payload() -> serde_json::Value {
        json!({
            "blockUser": true,
            "blockedPublicID": "creator-a",
            "contentId": "content-1",
            "id": "6F9619FF-8B86-D011-B42D-00C04FC964FF",
            "reasons": ["hateSpeech"],
            "timestamp": "2026-10-02T12:00:00Z"
        })
    }

    #[test]
    fn accepts_the_ios_payload() {
        let r = submission(ios_payload()).unwrap();
        assert_eq!(r.id.to_string(), "6f9619ff-8b86-d011-b42d-00c04fc964ff");
        assert_eq!(r.reasons, vec![Reason::HateSpeech]);
        assert!(r.blocked_on_device);
        assert_eq!(r.creator_subject.as_deref(), Some("creator-a"));
        assert_eq!(r.content_id.as_deref(), Some("content-1"));
        assert_eq!(r.note, None);
        assert_eq!(r.app_version, None);
    }

    #[test]
    fn accepts_every_ios_reason() {
        for raw in [
            "spam",
            "harassment",
            "hateSpeech",
            "violence",
            "adultContent",
            "copyright",
            "privacy",
            "misinformation",
            "other",
        ] {
            let mut p = ios_payload();
            p["reasons"] = json!([raw]);
            assert!(submission(p).is_ok(), "{raw}");
        }
    }

    #[test]
    fn accepts_null_targets_for_a_files_import() {
        let mut p = ios_payload();
        p["blockedPublicID"] = json!(null);
        p["contentId"] = json!(null);
        p["blockUser"] = json!(false);
        let r = submission(p).unwrap();
        assert_eq!(r.creator_subject, None);
        assert_eq!(r.content_id, None);
    }

    #[test]
    fn accepts_app_version_and_note() {
        let mut p = ios_payload();
        p["appVersion"] = json!("App: Arkavo 3.0 (112)");
        p["note"] = json!("  first\r\nsecond\u{0007}  ");
        let r = submission(p).unwrap();
        assert_eq!(r.app_version.as_deref(), Some("App: Arkavo 3.0 (112)"));
        assert_eq!(r.note.as_deref(), Some("first\nsecond"));
    }

    #[test]
    fn whitespace_note_is_no_note() {
        let mut p = ios_payload();
        p["note"] = json!(" \n\t\u{0001} ");
        assert_eq!(submission(p).unwrap().note, None);
    }

    #[test]
    fn note_bound_counts_graphemes() {
        let mut p = ios_payload();
        // 1000 family emoji: 7 scalars each, one grapheme each.
        p["note"] = json!("👨‍👩‍👧‍👦".repeat(NOTE_LIMIT));
        assert!(submission(p).is_ok());
        let mut p = ios_payload();
        p["note"] = json!("a".repeat(NOTE_LIMIT + 1));
        assert_eq!(submission(p).unwrap_err(), "note exceeds 1000 characters");
    }

    #[test]
    fn refuses_a_reporter_field() {
        let mut p = ios_payload();
        p["reporter"] = json!("someone");
        assert!(submission(p).unwrap_err().contains("unknown field"));
    }

    #[test]
    fn refuses_bad_fields() {
        let cases: Vec<(&str, serde_json::Value)> = vec![
            ("id", json!("not-a-uuid")),
            ("reasons", json!([])),
            ("reasons", json!(["nope"])),
            ("reasons", json!(["spam", "spam"])),
            ("timestamp", json!("yesterday")),
            ("contentId", json!("")),
            ("contentId", json!("has space")),
            ("blockedPublicID", json!("x".repeat(MAX_IDENTIFIER_LEN + 1))),
            ("appVersion", json!("bad\u{0000}")),
        ];
        for (k, v) in cases {
            let mut p = ios_payload();
            p[k] = v.clone();
            assert!(submission(p).is_err(), "{k}={v}");
        }
    }

    fn record() -> ReportRecord {
        ReportRecord::new(
            submission(ios_payload()).unwrap(),
            "u1".into(),
            1_000,
            86_400,
        )
    }

    #[test]
    fn new_record_is_received_with_retention() {
        let r = record();
        assert_eq!(r.status, Status::Received);
        assert_eq!(r.expires_at, 1_000 + 86_400);
        assert_eq!(r.reporter_subject, "u1");
        assert!(r.same_submission(&r.clone()));
        let mut other = r.clone();
        other.reporter_subject = "u2".into();
        assert!(!r.same_submission(&other));
    }

    fn update(v: serde_json::Value) -> StatusUpdate {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn first_response_is_recorded_once() {
        let r = record();
        let reviewing = update(json!({"status": "reviewing"}))
            .apply(&r, "mod", 1_060)
            .unwrap();
        assert_eq!(reviewing.first_response_at, Some(1_060));
        assert_eq!(reviewing.response_seconds, Some(60));
        assert_eq!(reviewing.resolved_at, None);
        let done = update(json!({"status": "dismissed", "note": "not a violation"}))
            .apply(&reviewing, "mod2", 2_000)
            .unwrap();
        assert_eq!(done.first_response_at, Some(1_060));
        assert_eq!(done.response_seconds, Some(60));
        assert_eq!(done.resolved_at, Some(2_000));
        assert_eq!(done.moderator_subject.as_deref(), Some("mod2"));
        assert_eq!(done.resolution_note.as_deref(), Some("not a violation"));
    }

    #[test]
    fn terminal_reports_do_not_change() {
        let r = record();
        let done = update(json!({"status": "dismissed"}))
            .apply(&r, "m", 1_100)
            .unwrap();
        for s in ["received", "reviewing", "actioned", "dismissed"] {
            let u = update(json!({"status": s, "actions": ["takedown"]}));
            assert!(u.apply(&done, "m", 1_200).is_err(), "{s}");
        }
        assert!(update(json!({"status": "received"}))
            .apply(&r, "m", 1_100)
            .is_err());
    }

    #[test]
    fn actions_follow_status_and_target() {
        let r = record();
        assert!(update(json!({"status": "actioned"}))
            .apply(&r, "m", 1)
            .is_err());
        assert!(
            update(json!({"status": "reviewing", "actions": ["suspend"]}))
                .apply(&r, "m", 1)
                .is_err()
        );
        assert!(
            update(json!({"status": "actioned", "actions": ["takedown", "takedown"]}))
                .apply(&r, "m", 1)
                .is_err()
        );
        let both = update(json!({"status": "actioned", "actions": ["takedown", "suspend"]}))
            .apply(&r, "m", 1_500)
            .unwrap();
        assert_eq!(both.actions, vec![Action::Takedown, Action::Suspend]);
        let mut no_content = r.clone();
        no_content.content_id = None;
        assert!(
            update(json!({"status": "actioned", "actions": ["takedown"]}))
                .apply(&no_content, "m", 1)
                .is_err()
        );
        let mut no_creator = r.clone();
        no_creator.creator_subject = None;
        assert!(
            update(json!({"status": "actioned", "actions": ["suspend"]}))
                .apply(&no_creator, "m", 1)
                .is_err()
        );
    }
}
