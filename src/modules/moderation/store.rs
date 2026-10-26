//! Report storage, one item per report keyed by the report ID, and the
//! per-account publishing suspensions (arkavo-rs#93), one item per account.

use super::report::{ReportRecord, Status};
use async_trait::async_trait;
use aws_sdk_dynamodb::types::AttributeValue;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The report's status changed since it was read.
    StatusChanged,
    Unavailable(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Inserted {
    Created,
    /// A record with this ID already exists; it was left unchanged.
    Existing(Box<ReportRecord>),
}

/// Position in a status queue: the last record returned.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Cursor {
    pub id: String,
    pub received_at: i64,
}

#[async_trait]
pub trait ReportStore: Send + Sync {
    /// Store a new report, never replacing one with the same ID.
    async fn insert(&self, record: &ReportRecord) -> Result<Inserted, StoreError>;
    async fn get(&self, id: &str) -> Result<Option<ReportRecord>, StoreError>;
    /// Replace the record only while its stored status is still `expected`.
    async fn update(&self, record: &ReportRecord, expected: Status) -> Result<(), StoreError>;
    /// Reports with `status`, oldest first.
    async fn list(
        &self,
        status: Status,
        limit: usize,
        after: Option<Cursor>,
    ) -> Result<(Vec<ReportRecord>, Option<Cursor>), StoreError>;
}

/// An account's publishing suspension, written when a report is actioned with
/// `suspend`. A lift is recorded on it, never deleted, so who suspended and who
/// lifted, when and why, stay on record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Suspension {
    /// The account's token `sub`, without the `arkavo:` prefix.
    pub subject: String,
    pub since: i64,
    pub report_id: String,
    pub moderator: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifted: Option<Lift>,
}

impl Suspension {
    pub fn is_active(&self) -> bool {
        self.lifted.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lift {
    pub at: i64,
    pub moderator: String,
    pub reason: String,
}

/// Earlier, lifted suspensions kept with an account's current one.
pub const MAX_EARLIER_SUSPENSIONS: usize = 20;

/// What is stored per account: the current suspension (active or lifted) and
/// the ones lifted before it, newest last.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuspensionHistory {
    pub current: Suspension,
    #[serde(default)]
    pub earlier: Vec<Suspension>,
}

impl SuspensionHistory {
    /// The history after suspending, or `None` when the account is already
    /// suspended: it keeps its first record, so `since` and `reportId` name
    /// the original action.
    pub fn suspended(existing: Option<Self>, new: &Suspension) -> Option<Self> {
        match existing {
            None => Some(Self {
                current: new.clone(),
                earlier: Vec::new(),
            }),
            Some(h) if h.current.is_active() => None,
            Some(mut h) => {
                h.earlier
                    .push(std::mem::replace(&mut h.current, new.clone()));
                let excess = h.earlier.len().saturating_sub(MAX_EARLIER_SUSPENSIONS);
                h.earlier.drain(..excess);
                Some(h)
            }
        }
    }

    /// The history after a lift, or `None` when nothing is suspended. With
    /// `only_report`, only a suspension recorded by that report is lifted, so
    /// a failed PATCH withdraws its own suspension and no one else's.
    pub fn lifted(existing: Option<Self>, lift: &Lift, only_report: Option<&str>) -> Option<Self> {
        let mut h = existing.filter(|h| {
            h.current.is_active() && only_report.is_none_or(|id| h.current.report_id == id)
        })?;
        h.current.lifted = Some(lift.clone());
        Some(h)
    }
}

#[async_trait]
pub trait SuspensionStore: Send + Sync {
    /// Record a suspension, unless the account is already suspended; `true`
    /// when this call recorded it.
    async fn suspend(&self, suspension: &Suspension) -> Result<bool, StoreError>;
    /// The account's current suspension, active or lifted.
    async fn get(&self, subject: &str) -> Result<Option<Suspension>, StoreError>;
    /// Record a lift on the active suspension (only if `only_report` recorded
    /// it, when given); `false` when there was none to lift.
    async fn lift(
        &self,
        subject: &str,
        lift: &Lift,
        only_report: Option<&str>,
    ) -> Result<bool, StoreError>;
}

/// Suspensions share the reports table, one item per account under the key
/// `suspension#<subject>`, which no report ID (a UUID) can take. The item has
/// no `status`, so it stays out of the queue index, and no `expires_at`, so it
/// never expires. `version` guards the read-modify-write.
pub struct DynamoSuspensionStore {
    client: aws_sdk_dynamodb::Client,
    table: String,
}

/// Attempts at a read-modify-write before a concurrent change is reported.
const SUSPENSION_WRITE_ATTEMPTS: usize = 3;

fn suspension_item_key(subject: &str) -> String {
    format!("suspension#{subject}")
}

impl DynamoSuspensionStore {
    pub fn new(client: aws_sdk_dynamodb::Client, table: String) -> Self {
        Self { client, table }
    }

    async fn load(&self, subject: &str) -> Result<Option<(SuspensionHistory, i64)>, StoreError> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("report_id", AttributeValue::S(suspension_item_key(subject)))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| unavailable(aws_sdk_dynamodb::error::DisplayErrorContext(e)))?;
        let Some(item) = out.item() else {
            return Ok(None);
        };
        let json = item
            .get("record")
            .and_then(|v| v.as_s().ok())
            .ok_or_else(|| StoreError::Unavailable("item has no record".into()))?;
        let history = serde_json::from_str(json)
            .map_err(|e| StoreError::Unavailable(format!("decode: {e}")))?;
        let version = item
            .get("version")
            .and_then(|v| v.as_n().ok())
            .and_then(|n| n.parse::<i64>().ok())
            .ok_or_else(|| StoreError::Unavailable("item has no version".into()))?;
        Ok(Some((history, version)))
    }

    /// Write `history` only if the item is still at `expected` (absent when
    /// `None`). A concurrent write is `StatusChanged`.
    async fn save(
        &self,
        history: &SuspensionHistory,
        expected: Option<i64>,
    ) -> Result<(), StoreError> {
        let json = serde_json::to_string(history)
            .map_err(|e| StoreError::Unavailable(format!("encode: {e}")))?;
        let next = expected.map_or(1, |v| v + 1);
        let put = self
            .client
            .put_item()
            .table_name(&self.table)
            .item(
                "report_id",
                AttributeValue::S(suspension_item_key(&history.current.subject)),
            )
            .item("record", AttributeValue::S(json))
            .item("version", AttributeValue::N(next.to_string()));
        let put = match expected {
            None => put.condition_expression("attribute_not_exists(report_id)"),
            Some(v) => put
                .condition_expression("version = :v")
                .expression_attribute_values(":v", AttributeValue::N(v.to_string())),
        };
        match put.send().await {
            Ok(_) => Ok(()),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|s| s.is_conditional_check_failed_exception()) =>
            {
                Err(StoreError::StatusChanged)
            }
            Err(e) => Err(unavailable(aws_sdk_dynamodb::error::DisplayErrorContext(e))),
        }
    }

    /// Apply `change` to the stored history and save it, retrying when another
    /// writer got there first. `Ok(false)` when `change` wants no write.
    async fn update(
        &self,
        subject: &str,
        change: impl Fn(Option<SuspensionHistory>) -> Option<SuspensionHistory> + Send + Sync,
    ) -> Result<bool, StoreError> {
        for _ in 0..SUSPENSION_WRITE_ATTEMPTS {
            let loaded = self.load(subject).await?;
            let version = loaded.as_ref().map(|(_, v)| *v);
            let Some(next) = change(loaded.map(|(h, _)| h)) else {
                return Ok(false);
            };
            match self.save(&next, version).await {
                Ok(()) => return Ok(true),
                Err(StoreError::StatusChanged) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(StoreError::StatusChanged)
    }
}

#[async_trait]
impl SuspensionStore for DynamoSuspensionStore {
    async fn suspend(&self, suspension: &Suspension) -> Result<bool, StoreError> {
        self.update(&suspension.subject, |h| {
            SuspensionHistory::suspended(h, suspension)
        })
        .await
    }

    async fn get(&self, subject: &str) -> Result<Option<Suspension>, StoreError> {
        Ok(self.load(subject).await?.map(|(h, _)| h.current))
    }

    async fn lift(
        &self,
        subject: &str,
        lift: &Lift,
        only_report: Option<&str>,
    ) -> Result<bool, StoreError> {
        self.update(subject, |h| SuspensionHistory::lifted(h, lift, only_report))
            .await
    }
}

/// DynamoDB table: hash key `report_id`; GSI (`status`, `received_at`);
/// TTL on `expires_at`, set only on resolved reports. The record itself is
/// the JSON in `record`.
pub struct DynamoReportStore {
    client: aws_sdk_dynamodb::Client,
    table: String,
    status_index: String,
}

impl DynamoReportStore {
    pub fn new(client: aws_sdk_dynamodb::Client, table: String, status_index: String) -> Self {
        Self {
            client,
            table,
            status_index,
        }
    }

    fn item(record: &ReportRecord) -> Result<HashMap<String, AttributeValue>, StoreError> {
        let json = serde_json::to_string(record)
            .map_err(|e| StoreError::Unavailable(format!("encode: {e}")))?;
        let mut item = HashMap::from([
            (
                "report_id".to_string(),
                AttributeValue::S(record.id.clone()),
            ),
            (
                "status".to_string(),
                AttributeValue::S(record.status.as_str().to_string()),
            ),
            (
                "received_at".to_string(),
                AttributeValue::N(record.received_at.to_string()),
            ),
            ("record".to_string(), AttributeValue::S(json)),
        ]);
        if let Some(t) = record.expires_at {
            item.insert("expires_at".to_string(), AttributeValue::N(t.to_string()));
        }
        Ok(item)
    }

    fn record(item: &HashMap<String, AttributeValue>) -> Result<ReportRecord, StoreError> {
        let json = item
            .get("record")
            .and_then(|v| v.as_s().ok())
            .ok_or_else(|| StoreError::Unavailable("item has no record".into()))?;
        serde_json::from_str(json).map_err(|e| StoreError::Unavailable(format!("decode: {e}")))
    }
}

fn unavailable<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Unavailable(e.to_string())
}

#[async_trait]
impl ReportStore for DynamoReportStore {
    async fn insert(&self, record: &ReportRecord) -> Result<Inserted, StoreError> {
        let put = self
            .client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(Self::item(record)?))
            .condition_expression("attribute_not_exists(report_id)")
            .send()
            .await;
        match put {
            Ok(_) => Ok(Inserted::Created),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|s| s.is_conditional_check_failed_exception()) =>
            {
                match self.get(&record.id).await? {
                    Some(existing) => Ok(Inserted::Existing(Box::new(existing))),
                    None => Err(StoreError::Unavailable(
                        "conditional put failed but item is missing".into(),
                    )),
                }
            }
            Err(e) => Err(unavailable(aws_sdk_dynamodb::error::DisplayErrorContext(e))),
        }
    }

    async fn get(&self, id: &str) -> Result<Option<ReportRecord>, StoreError> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("report_id", AttributeValue::S(id.to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| unavailable(aws_sdk_dynamodb::error::DisplayErrorContext(e)))?;
        out.item().map(Self::record).transpose()
    }

    async fn update(&self, record: &ReportRecord, expected: Status) -> Result<(), StoreError> {
        let put = self
            .client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(Self::item(record)?))
            .condition_expression("#s = :expected")
            .expression_attribute_names("#s", "status")
            .expression_attribute_values(":expected", AttributeValue::S(expected.as_str().into()))
            .send()
            .await;
        match put {
            Ok(_) => Ok(()),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|s| s.is_conditional_check_failed_exception()) =>
            {
                Err(StoreError::StatusChanged)
            }
            Err(e) => Err(unavailable(aws_sdk_dynamodb::error::DisplayErrorContext(e))),
        }
    }

    async fn list(
        &self,
        status: Status,
        limit: usize,
        after: Option<Cursor>,
    ) -> Result<(Vec<ReportRecord>, Option<Cursor>), StoreError> {
        let start = after.map(|c| {
            HashMap::from([
                ("report_id".to_string(), AttributeValue::S(c.id)),
                (
                    "status".to_string(),
                    AttributeValue::S(status.as_str().to_string()),
                ),
                (
                    "received_at".to_string(),
                    AttributeValue::N(c.received_at.to_string()),
                ),
            ])
        });
        let out = self
            .client
            .query()
            .table_name(&self.table)
            .index_name(&self.status_index)
            .key_condition_expression("#s = :s")
            .expression_attribute_names("#s", "status")
            .expression_attribute_values(":s", AttributeValue::S(status.as_str().into()))
            .scan_index_forward(true)
            .limit(i32::try_from(limit).unwrap_or(i32::MAX))
            .set_exclusive_start_key(start)
            .send()
            .await
            .map_err(|e| unavailable(aws_sdk_dynamodb::error::DisplayErrorContext(e)))?;
        let records = out
            .items()
            .iter()
            .map(Self::record)
            .collect::<Result<Vec<_>, _>>()?;
        let next = if out.last_evaluated_key().is_some() {
            records.last().map(|r| Cursor {
                id: r.id.clone(),
                received_at: r.received_at,
            })
        } else {
            None
        };
        Ok((records, next))
    }
}

#[cfg(test)]
pub mod memory {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct MemorySuspensionStore {
        pub records: Mutex<HashMap<String, SuspensionHistory>>,
        pub fail: Mutex<bool>,
    }

    impl MemorySuspensionStore {
        fn check(&self) -> Result<(), StoreError> {
            if *self.fail.lock().unwrap() {
                Err(StoreError::Unavailable("down".into()))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl SuspensionStore for MemorySuspensionStore {
        async fn suspend(&self, suspension: &Suspension) -> Result<bool, StoreError> {
            self.check()?;
            let mut m = self.records.lock().unwrap();
            let existing = m.get(&suspension.subject).cloned();
            match SuspensionHistory::suspended(existing, suspension) {
                Some(next) => {
                    m.insert(suspension.subject.clone(), next);
                    Ok(true)
                }
                None => Ok(false),
            }
        }

        async fn get(&self, subject: &str) -> Result<Option<Suspension>, StoreError> {
            self.check()?;
            Ok(self
                .records
                .lock()
                .unwrap()
                .get(subject)
                .map(|h| h.current.clone()))
        }

        async fn lift(
            &self,
            subject: &str,
            lift: &Lift,
            only_report: Option<&str>,
        ) -> Result<bool, StoreError> {
            self.check()?;
            let mut m = self.records.lock().unwrap();
            let existing = m.get(subject).cloned();
            match SuspensionHistory::lifted(existing, lift, only_report) {
                Some(next) => {
                    m.insert(subject.to_string(), next);
                    Ok(true)
                }
                None => Ok(false),
            }
        }
    }

    #[derive(Default)]
    pub struct MemoryReportStore {
        pub records: Mutex<HashMap<String, ReportRecord>>,
        pub fail: Mutex<bool>,
    }

    impl MemoryReportStore {
        fn check(&self) -> Result<(), StoreError> {
            if *self.fail.lock().unwrap() {
                Err(StoreError::Unavailable("down".into()))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl ReportStore for MemoryReportStore {
        async fn insert(&self, record: &ReportRecord) -> Result<Inserted, StoreError> {
            self.check()?;
            let mut m = self.records.lock().unwrap();
            if let Some(existing) = m.get(&record.id) {
                return Ok(Inserted::Existing(Box::new(existing.clone())));
            }
            m.insert(record.id.clone(), record.clone());
            Ok(Inserted::Created)
        }

        async fn get(&self, id: &str) -> Result<Option<ReportRecord>, StoreError> {
            self.check()?;
            Ok(self.records.lock().unwrap().get(id).cloned())
        }

        async fn update(&self, record: &ReportRecord, expected: Status) -> Result<(), StoreError> {
            self.check()?;
            let mut m = self.records.lock().unwrap();
            match m.get(&record.id) {
                Some(cur) if cur.status == expected => {
                    m.insert(record.id.clone(), record.clone());
                    Ok(())
                }
                _ => Err(StoreError::StatusChanged),
            }
        }

        async fn list(
            &self,
            status: Status,
            limit: usize,
            after: Option<Cursor>,
        ) -> Result<(Vec<ReportRecord>, Option<Cursor>), StoreError> {
            self.check()?;
            let mut all: Vec<_> = self
                .records
                .lock()
                .unwrap()
                .values()
                .filter(|r| r.status == status)
                .cloned()
                .collect();
            all.sort_by(|a, b| (a.received_at, &a.id).cmp(&(b.received_at, &b.id)));
            let start = match &after {
                Some(c) => all
                    .iter()
                    .position(|r| (r.received_at, &r.id) > (c.received_at, &c.id))
                    .unwrap_or(all.len()),
                None => 0,
            };
            let page: Vec<_> = all[start..].iter().take(limit).cloned().collect();
            let next = (start + page.len() < all.len()).then(|| {
                let last = page.last().unwrap();
                Cursor {
                    id: last.id.clone(),
                    received_at: last.received_at,
                }
            });
            Ok((page, next))
        }
    }
}

/// Runs against DynamoDB Local when `DYNAMODB_ENDPOINT` is set:
/// `docker run --rm -p 8000:8000 amazon/dynamodb-local -jar DynamoDBLocal.jar -inMemory`, then
/// `DYNAMODB_ENDPOINT=http://localhost:8000 AWS_REGION=us-east-1 AWS_ACCESS_KEY_ID=x
/// AWS_SECRET_ACCESS_KEY=x cargo test --bin arks dynamodb_local -- --ignored`.
#[cfg(test)]
mod dynamodb_local {
    use super::*;
    use crate::modules::moderation::report::{Reason, ValidReport};
    use aws_sdk_dynamodb::types::{
        AttributeDefinition, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType,
        Projection, ProjectionType, ScalarAttributeType,
    };

    const INDEX: &str = "status-received_at-index";

    fn attr(name: &str, t: ScalarAttributeType) -> AttributeDefinition {
        AttributeDefinition::builder()
            .attribute_name(name)
            .attribute_type(t)
            .build()
            .unwrap()
    }

    fn key(name: &str, t: KeyType) -> KeySchemaElement {
        KeySchemaElement::builder()
            .attribute_name(name)
            .key_type(t)
            .build()
            .unwrap()
    }

    fn report(received_at: i64) -> ReportRecord {
        ReportRecord::new(
            ValidReport {
                id: uuid::Uuid::new_v4(),
                reasons: vec![Reason::Spam],
                blocked_on_device: false,
                client_timestamp: chrono::Utc::now(),
                content_id: Some("content-1".into()),
                creator_subject: Some("creator-a".into()),
                app_version: None,
                note: Some("look".into()),
            },
            "reporter".into(),
            received_at,
        )
    }

    #[tokio::test]
    #[ignore]
    async fn dynamodb_local_store_round_trip() {
        let endpoint = std::env::var("DYNAMODB_ENDPOINT").expect("DYNAMODB_ENDPOINT");
        let shared = aws_config::load_from_env().await;
        let conf = aws_sdk_dynamodb::config::Builder::from(&shared)
            .endpoint_url(endpoint)
            .build();
        let client = aws_sdk_dynamodb::Client::from_conf(conf);
        let table = format!("test-moderation-{}", uuid::Uuid::new_v4());
        client
            .create_table()
            .table_name(&table)
            .attribute_definitions(attr("report_id", ScalarAttributeType::S))
            .attribute_definitions(attr("status", ScalarAttributeType::S))
            .attribute_definitions(attr("received_at", ScalarAttributeType::N))
            .key_schema(key("report_id", KeyType::Hash))
            .global_secondary_indexes(
                GlobalSecondaryIndex::builder()
                    .index_name(INDEX)
                    .key_schema(key("status", KeyType::Hash))
                    .key_schema(key("received_at", KeyType::Range))
                    .projection(
                        Projection::builder()
                            .projection_type(ProjectionType::All)
                            .build(),
                    )
                    .build()
                    .unwrap(),
            )
            .billing_mode(BillingMode::PayPerRequest)
            .send()
            .await
            .expect("create table");
        let store = DynamoReportStore::new(client.clone(), table.clone(), INDEX.into());

        // Insert once; a second insert with the same ID returns the original.
        let first = report(100);
        assert_eq!(store.insert(&first).await.unwrap(), Inserted::Created);
        let mut clash = first.clone();
        clash.note = Some("changed".into());
        match store.insert(&clash).await.unwrap() {
            Inserted::Existing(e) => assert_eq!(*e, first),
            other => panic!("{other:?}"),
        }
        assert_eq!(store.get(&first.id).await.unwrap(), Some(first.clone()));
        let raw = client
            .get_item()
            .table_name(&table)
            .key("report_id", AttributeValue::S(first.id.clone()))
            .send()
            .await
            .unwrap();
        assert!(!raw.item().unwrap().contains_key("expires_at"));

        // Page the received queue, oldest first, through a cursor.
        let mut ids = vec![first.id.clone()];
        for t in [200, 300] {
            let r = report(t);
            ids.push(r.id.clone());
            store.insert(&r).await.unwrap();
        }
        let (page1, next) = store.list(Status::Received, 2, None).await.unwrap();
        assert_eq!(
            page1.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
            ids[..2]
        );
        let (page2, _) = store.list(Status::Received, 2, next).await.unwrap();
        assert_eq!(page2[0].id, ids[2]);

        // Conditional update: only from the expected status. Resolution sets the TTL.
        let mut resolved = first.clone();
        resolved.status = Status::Dismissed;
        resolved.expires_at = Some(1_000);
        assert_eq!(
            store.update(&resolved, Status::Reviewing).await,
            Err(StoreError::StatusChanged)
        );
        store.update(&resolved, Status::Received).await.unwrap();
        let raw = client
            .get_item()
            .table_name(&table)
            .key("report_id", AttributeValue::S(first.id.clone()))
            .send()
            .await
            .unwrap();
        assert_eq!(
            raw.item().unwrap()["expires_at"],
            AttributeValue::N("1000".into())
        );
        let (dismissed, _) = store.list(Status::Dismissed, 10, None).await.unwrap();
        assert_eq!(dismissed.len(), 1);

        client
            .delete_table()
            .table_name(&table)
            .send()
            .await
            .unwrap();
    }
    #[tokio::test]
    #[ignore]
    async fn dynamodb_local_suspension_round_trip() {
        let endpoint = std::env::var("DYNAMODB_ENDPOINT").expect("DYNAMODB_ENDPOINT");
        let shared = aws_config::load_from_env().await;
        let conf = aws_sdk_dynamodb::config::Builder::from(&shared)
            .endpoint_url(endpoint)
            .build();
        let client = aws_sdk_dynamodb::Client::from_conf(conf);
        let table = format!("test-moderation-{}", uuid::Uuid::new_v4());
        client
            .create_table()
            .table_name(&table)
            .attribute_definitions(attr("report_id", ScalarAttributeType::S))
            .attribute_definitions(attr("status", ScalarAttributeType::S))
            .attribute_definitions(attr("received_at", ScalarAttributeType::N))
            .key_schema(key("report_id", KeyType::Hash))
            .global_secondary_indexes(
                GlobalSecondaryIndex::builder()
                    .index_name(INDEX)
                    .key_schema(key("status", KeyType::Hash))
                    .key_schema(key("received_at", KeyType::Range))
                    .projection(
                        Projection::builder()
                            .projection_type(ProjectionType::All)
                            .build(),
                    )
                    .build()
                    .unwrap(),
            )
            .billing_mode(BillingMode::PayPerRequest)
            .send()
            .await
            .expect("create table");
        let reports = DynamoReportStore::new(client.clone(), table.clone(), INDEX.into());
        let store = DynamoSuspensionStore::new(client.clone(), table.clone());

        let first = Suspension {
            subject: "creator-a".into(),
            since: 100,
            report_id: "r1".into(),
            moderator: "m1".into(),
            reason: "first".into(),
            lifted: None,
        };
        assert_eq!(store.get("creator-a").await.unwrap(), None);
        assert!(store.suspend(&first).await.unwrap());
        // A second suspension while active keeps the first record.
        let mut second = first.clone();
        second.since = 200;
        second.report_id = "r2".into();
        assert!(!store.suspend(&second).await.unwrap());
        assert_eq!(store.get("creator-a").await.unwrap(), Some(first.clone()));
        // The item stays out of the moderators' queues.
        for status in [Status::Received, Status::Actioned] {
            assert!(reports.list(status, 10, None).await.unwrap().0.is_empty());
        }

        let lift = Lift {
            at: 300,
            moderator: "m2".into(),
            reason: "appeal upheld".into(),
        };
        assert!(!store.lift("creator-a", &lift, Some("r2")).await.unwrap());
        assert!(store.lift("creator-a", &lift, Some("r1")).await.unwrap());
        assert!(!store.lift("creator-a", &lift, None).await.unwrap());
        let lifted = store.get("creator-a").await.unwrap().unwrap();
        assert_eq!(lifted.lifted, Some(lift));

        // Suspended again: the lifted record moves to the history.
        store.suspend(&second).await.unwrap();
        assert_eq!(store.get("creator-a").await.unwrap(), Some(second));
        let (history, version) = store.load("creator-a").await.unwrap().unwrap();
        assert_eq!(history.earlier, vec![lifted]);
        assert_eq!(version, 3);

        client
            .delete_table()
            .table_name(&table)
            .send()
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod suspension_history {
    use super::*;

    fn suspension(report: &str) -> Suspension {
        Suspension {
            subject: "creator-a".into(),
            since: 1,
            report_id: report.into(),
            moderator: "m1".into(),
            reason: "why".into(),
            lifted: None,
        }
    }

    fn lift() -> Lift {
        Lift {
            at: 2,
            moderator: "m2".into(),
            reason: "lifted".into(),
        }
    }

    #[test]
    fn suspending_keeps_the_first_active_record() {
        let h = SuspensionHistory::suspended(None, &suspension("r1")).unwrap();
        assert_eq!(h.current.report_id, "r1");
        assert_eq!(
            SuspensionHistory::suspended(Some(h), &suspension("r2")),
            None
        );
    }

    #[test]
    fn a_lift_is_recorded_and_a_new_suspension_keeps_it() {
        assert_eq!(SuspensionHistory::lifted(None, &lift(), None), None);
        let h = SuspensionHistory::suspended(None, &suspension("r1")).unwrap();
        let h = SuspensionHistory::lifted(Some(h), &lift(), None).unwrap();
        assert!(!h.current.is_active());
        assert_eq!(
            SuspensionHistory::lifted(Some(h.clone()), &lift(), None),
            None
        );
        let again = SuspensionHistory::suspended(Some(h.clone()), &suspension("r2")).unwrap();
        assert_eq!(again.current.report_id, "r2");
        assert_eq!(again.earlier, vec![h.current]);
    }

    #[test]
    fn a_withdrawal_lifts_only_the_named_reports_suspension() {
        let h = SuspensionHistory::suspended(None, &suspension("r1")).unwrap();
        assert_eq!(
            SuspensionHistory::lifted(Some(h.clone()), &lift(), Some("r2")),
            None
        );
        assert!(SuspensionHistory::lifted(Some(h), &lift(), Some("r1")).is_some());
    }

    #[test]
    fn history_is_bounded() {
        let mut h = SuspensionHistory::suspended(None, &suspension("r0")).unwrap();
        for i in 1..=(MAX_EARLIER_SUSPENSIONS + 5) {
            h = SuspensionHistory::lifted(Some(h), &lift(), None).unwrap();
            h = SuspensionHistory::suspended(Some(h), &suspension(&format!("r{i}"))).unwrap();
        }
        assert_eq!(h.earlier.len(), MAX_EARLIER_SUSPENSIONS);
        assert_eq!(h.earlier[0].report_id, "r5");
    }
}
