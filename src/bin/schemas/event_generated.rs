// automatically generated by the FlatBuffers compiler, do not modify

// @generated

extern crate flatbuffers;

#[allow(unused_imports, dead_code)]
pub mod arkavo {
  extern crate flatbuffers;

    #[deprecated(
        since = "2.0.0",
        note = "Use associated constants instead. This will no longer be generated in 2021."
    )]
    pub const ENUM_MIN_ACTION_TYPE: i8 = 0;
    #[deprecated(
        since = "2.0.0",
        note = "Use associated constants instead. This will no longer be generated in 2021."
    )]
    pub const ENUM_MAX_ACTION_TYPE: i8 = 4;
    #[deprecated(
        since = "2.0.0",
        note = "Use associated constants instead. This will no longer be generated in 2021."
    )]
    #[allow(non_camel_case_types)]
    pub const ENUM_VALUES_ACTION_TYPE: [ActionType; 5] = [
        ActionType::join,
        ActionType::apply,
        ActionType::approve,
        ActionType::leave,
        ActionType::sendMessage,
    ];

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    #[repr(transparent)]
    pub struct ActionType(pub i8);
    #[allow(non_upper_case_globals)]
    impl ActionType {
        pub const join: Self = Self(0);
        pub const apply: Self = Self(1);
        pub const approve: Self = Self(2);
        pub const leave: Self = Self(3);
        pub const sendMessage: Self = Self(4);

        pub const ENUM_MIN: i8 = 0;
        pub const ENUM_MAX: i8 = 4;
        pub const ENUM_VALUES: &'static [Self] = &[
            Self::join,
            Self::apply,
            Self::approve,
            Self::leave,
            Self::sendMessage,
        ];
        /// Returns the variant's name or "" if unknown.
        pub fn variant_name(self) -> Option<&'static str> {
            match self {
                Self::join => Some("join"),
                Self::apply => Some("apply"),
                Self::approve => Some("approve"),
                Self::leave => Some("leave"),
                Self::sendMessage => Some("sendMessage"),
                _ => None,
            }
        }
    }
    impl core::fmt::Debug for ActionType {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            if let Some(name) = self.variant_name() {
                f.write_str(name)
            } else {
                f.write_fmt(format_args!("<UNKNOWN {:?}>", self.0))
            }
        }
    }
    impl<'a> flatbuffers::Follow<'a> for ActionType {
        type Inner = Self;
        #[inline]
        unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
            let b = flatbuffers::read_scalar_at::<i8>(buf, loc);
            Self(b)
        }
    }

    impl flatbuffers::Push for ActionType {
        type Output = ActionType;
        #[inline]
        unsafe fn push(&self, dst: &mut [u8], _written_len: usize) {
            flatbuffers::emplace_scalar::<i8>(dst, self.0);
        }
    }

    impl flatbuffers::EndianScalar for ActionType {
        type Scalar = i8;
        #[inline]
        fn to_little_endian(self) -> i8 {
            self.0.to_le()
        }
        #[inline]
        #[allow(clippy::wrong_self_convention)]
        fn from_little_endian(v: i8) -> Self {
            let b = i8::from_le(v);
            Self(b)
        }
    }

    impl flatbuffers::Verifiable for ActionType {
        #[inline]
        fn run_verifier(
          v: &mut flatbuffers::Verifier,
          pos: usize,
        ) -> Result<(), flatbuffers::InvalidFlatbuffer> {
            use self::flatbuffers::Verifiable;
            i8::run_verifier(v, pos)
        }
    }

    impl flatbuffers::SimpleToVerifyInSlice for ActionType {}
    #[deprecated(
        since = "2.0.0",
        note = "Use associated constants instead. This will no longer be generated in 2021."
    )]
    pub const ENUM_MIN_ACTION_STATUS: i8 = 0;
    #[deprecated(
        since = "2.0.0",
        note = "Use associated constants instead. This will no longer be generated in 2021."
    )]
    pub const ENUM_MAX_ACTION_STATUS: i8 = 3;
    #[deprecated(
        since = "2.0.0",
        note = "Use associated constants instead. This will no longer be generated in 2021."
    )]
    #[allow(non_camel_case_types)]
    pub const ENUM_VALUES_ACTION_STATUS: [ActionStatus; 4] = [
        ActionStatus::preparing,
        ActionStatus::fulfilling,
        ActionStatus::fulfilled,
        ActionStatus::failed,
    ];

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    #[repr(transparent)]
    pub struct ActionStatus(pub i8);
    #[allow(non_upper_case_globals)]
    impl ActionStatus {
        pub const preparing: Self = Self(0);
        pub const fulfilling: Self = Self(1);
        pub const fulfilled: Self = Self(2);
        pub const failed: Self = Self(3);

        pub const ENUM_MIN: i8 = 0;
        pub const ENUM_MAX: i8 = 3;
        pub const ENUM_VALUES: &'static [Self] = &[
            Self::preparing,
            Self::fulfilling,
            Self::fulfilled,
            Self::failed,
        ];
        /// Returns the variant's name or "" if unknown.
        pub fn variant_name(self) -> Option<&'static str> {
            match self {
                Self::preparing => Some("preparing"),
                Self::fulfilling => Some("fulfilling"),
                Self::fulfilled => Some("fulfilled"),
                Self::failed => Some("failed"),
                _ => None,
            }
        }
    }
    impl core::fmt::Debug for ActionStatus {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            if let Some(name) = self.variant_name() {
                f.write_str(name)
            } else {
                f.write_fmt(format_args!("<UNKNOWN {:?}>", self.0))
            }
        }
    }
    impl<'a> flatbuffers::Follow<'a> for ActionStatus {
        type Inner = Self;
        #[inline]
        unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
            let b = flatbuffers::read_scalar_at::<i8>(buf, loc);
            Self(b)
        }
    }

    impl flatbuffers::Push for ActionStatus {
        type Output = ActionStatus;
        #[inline]
        unsafe fn push(&self, dst: &mut [u8], _written_len: usize) {
            flatbuffers::emplace_scalar::<i8>(dst, self.0);
        }
    }

    impl flatbuffers::EndianScalar for ActionStatus {
        type Scalar = i8;
        #[inline]
        fn to_little_endian(self) -> i8 {
            self.0.to_le()
        }
        #[inline]
        #[allow(clippy::wrong_self_convention)]
        fn from_little_endian(v: i8) -> Self {
            let b = i8::from_le(v);
            Self(b)
        }
    }

    impl flatbuffers::Verifiable for ActionStatus {
        #[inline]
        fn run_verifier(
          v: &mut flatbuffers::Verifier,
          pos: usize,
        ) -> Result<(), flatbuffers::InvalidFlatbuffer> {
            use self::flatbuffers::Verifiable;
            i8::run_verifier(v, pos)
        }
    }

    impl flatbuffers::SimpleToVerifyInSlice for ActionStatus {}
    #[deprecated(
        since = "2.0.0",
        note = "Use associated constants instead. This will no longer be generated in 2021."
    )]
    pub const ENUM_MIN_ENTITY_TYPE: i8 = 0;
    #[deprecated(
        since = "2.0.0",
        note = "Use associated constants instead. This will no longer be generated in 2021."
    )]
    pub const ENUM_MAX_ENTITY_TYPE: i8 = 1;
    #[deprecated(
        since = "2.0.0",
        note = "Use associated constants instead. This will no longer be generated in 2021."
    )]
    #[allow(non_camel_case_types)]
    pub const ENUM_VALUES_ENTITY_TYPE: [EntityType; 2] =
        [EntityType::stream_profile, EntityType::account_profile];

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    #[repr(transparent)]
    pub struct EntityType(pub i8);
    #[allow(non_upper_case_globals)]
    impl EntityType {
        pub const stream_profile: Self = Self(0);
        pub const account_profile: Self = Self(1);

        pub const ENUM_MIN: i8 = 0;
        pub const ENUM_MAX: i8 = 1;
        pub const ENUM_VALUES: &'static [Self] = &[Self::stream_profile, Self::account_profile];
        /// Returns the variant's name or "" if unknown.
        pub fn variant_name(self) -> Option<&'static str> {
            match self {
                Self::stream_profile => Some("stream_profile"),
                Self::account_profile => Some("account_profile"),
                _ => None,
            }
        }
    }
    impl core::fmt::Debug for EntityType {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            if let Some(name) = self.variant_name() {
                f.write_str(name)
            } else {
                f.write_fmt(format_args!("<UNKNOWN {:?}>", self.0))
            }
        }
    }
    impl<'a> flatbuffers::Follow<'a> for EntityType {
        type Inner = Self;
        #[inline]
        unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
            let b = flatbuffers::read_scalar_at::<i8>(buf, loc);
            Self(b)
        }
    }

    impl flatbuffers::Push for EntityType {
        type Output = EntityType;
        #[inline]
        unsafe fn push(&self, dst: &mut [u8], _written_len: usize) {
            flatbuffers::emplace_scalar::<i8>(dst, self.0);
        }
    }

    impl flatbuffers::EndianScalar for EntityType {
        type Scalar = i8;
        #[inline]
        fn to_little_endian(self) -> i8 {
            self.0.to_le()
        }
        #[inline]
        #[allow(clippy::wrong_self_convention)]
        fn from_little_endian(v: i8) -> Self {
            let b = i8::from_le(v);
            Self(b)
        }
    }

    impl flatbuffers::Verifiable for EntityType {
        #[inline]
        fn run_verifier(
          v: &mut flatbuffers::Verifier,
          pos: usize,
        ) -> Result<(), flatbuffers::InvalidFlatbuffer> {
            use self::flatbuffers::Verifiable;
            i8::run_verifier(v, pos)
        }
    }

    impl flatbuffers::SimpleToVerifyInSlice for EntityType {}
    pub enum EventOffset {}
    #[derive(Copy, Clone, PartialEq)]

    pub struct Event<'a> {
        pub _tab: flatbuffers::Table<'a>,
    }

    impl<'a> flatbuffers::Follow<'a> for Event<'a> {
        type Inner = Event<'a>;
        #[inline]
        unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
            Self {
                _tab: flatbuffers::Table::new(buf, loc),
            }
        }
    }

    impl<'a> Event<'a> {
        pub const VT_ACTION_TYPE: flatbuffers::VOffsetT = 4;

        #[inline]
        pub unsafe fn init_from_table(table: flatbuffers::Table<'a>) -> Self {
            Event { _tab: table }
        }
        #[allow(unused_mut)]
        pub fn create<
            'bldr: 'args,
            'args: 'mut_bldr,
            'mut_bldr,
            A: flatbuffers::Allocator + 'bldr,
        >(
          _fbb: &'mut_bldr mut flatbuffers::FlatBufferBuilder<'bldr, A>,
          args: &'args EventArgs,
        ) -> flatbuffers::WIPOffset<Event<'bldr>> {
            let mut builder = EventBuilder::new(_fbb);
            builder.add_action_type(args.action_type);
            builder.finish()
        }

        #[inline]
        pub fn action_type(&self) -> ActionType {
            // Safety:
            // Created from valid Table for this object
            // which contains a valid value in this slot
            unsafe {
                self._tab
                    .get::<ActionType>(Event::VT_ACTION_TYPE, Some(ActionType::join))
                    .unwrap()
            }
        }
    }

    impl flatbuffers::Verifiable for Event<'_> {
        #[inline]
        fn run_verifier(
          v: &mut flatbuffers::Verifier,
          pos: usize,
        ) -> Result<(), flatbuffers::InvalidFlatbuffer> {
          v.visit_table(pos)?
                .visit_field::<ActionType>("action_type", Self::VT_ACTION_TYPE, false)?
                .finish();
            Ok(())
        }
    }
    pub struct EventArgs {
        pub action_type: ActionType,
    }
    impl Default for EventArgs {
        #[inline]
        fn default() -> Self {
            EventArgs {
                action_type: ActionType::join,
            }
        }
    }

    pub struct EventBuilder<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> {
        fbb_: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
        start_: flatbuffers::WIPOffset<flatbuffers::TableUnfinishedWIPOffset>,
    }
    impl<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> EventBuilder<'a, 'b, A> {
        #[inline]
        pub fn add_action_type(&mut self, action_type: ActionType) {
            self.fbb_
                .push_slot::<ActionType>(Event::VT_ACTION_TYPE, action_type, ActionType::join);
        }
        #[inline]
        pub fn new(_fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>) -> EventBuilder<'a, 'b, A> {
            let start = _fbb.start_table();
            EventBuilder {
                fbb_: _fbb,
                start_: start,
            }
        }
        #[inline]
        pub fn finish(self) -> flatbuffers::WIPOffset<Event<'a>> {
            let o = self.fbb_.end_table(self.start_);
            flatbuffers::WIPOffset::new(o.value())
        }
    }

    impl core::fmt::Debug for Event<'_> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let mut ds = f.debug_struct("Event");
            ds.field("action_type", &self.action_type());
            ds.finish()
        }
    }
    pub enum UserEventOffset {}
    #[derive(Copy, Clone, PartialEq)]

    pub struct UserEvent<'a> {
        pub _tab: flatbuffers::Table<'a>,
    }

    impl<'a> flatbuffers::Follow<'a> for UserEvent<'a> {
        type Inner = UserEvent<'a>;
        #[inline]
        unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
            Self {
                _tab: flatbuffers::Table::new(buf, loc),
            }
        }
    }

    impl<'a> UserEvent<'a> {
        pub const VT_SOURCE_TYPE: flatbuffers::VOffsetT = 4;
        pub const VT_TARGET_TYPE: flatbuffers::VOffsetT = 6;
        pub const VT_SOURCE_ID: flatbuffers::VOffsetT = 8;
        pub const VT_TARGET_ID: flatbuffers::VOffsetT = 10;
        pub const VT_TIMESTAMP: flatbuffers::VOffsetT = 12;
        pub const VT_STATUS: flatbuffers::VOffsetT = 14;

        #[inline]
        pub unsafe fn init_from_table(table: flatbuffers::Table<'a>) -> Self {
            UserEvent { _tab: table }
        }
        #[allow(unused_mut)]
        pub fn create<
            'bldr: 'args,
            'args: 'mut_bldr,
            'mut_bldr,
            A: flatbuffers::Allocator + 'bldr,
        >(
          _fbb: &'mut_bldr mut flatbuffers::FlatBufferBuilder<'bldr, A>,
          args: &'args UserEventArgs<'args>,
        ) -> flatbuffers::WIPOffset<UserEvent<'bldr>> {
            let mut builder = UserEventBuilder::new(_fbb);
            builder.add_timestamp(args.timestamp);
            if let Some(x) = args.target_id {
                builder.add_target_id(x);
            }
            if let Some(x) = args.source_id {
                builder.add_source_id(x);
            }
            builder.add_status(args.status);
            builder.add_target_type(args.target_type);
            builder.add_source_type(args.source_type);
            builder.finish()
        }

        #[inline]
        pub fn source_type(&self) -> EntityType {
            // Safety:
            // Created from valid Table for this object
            // which contains a valid value in this slot
            unsafe {
                self._tab
                    .get::<EntityType>(UserEvent::VT_SOURCE_TYPE, Some(EntityType::stream_profile))
                    .unwrap()
            }
        }
        #[inline]
        pub fn target_type(&self) -> EntityType {
            // Safety:
            // Created from valid Table for this object
            // which contains a valid value in this slot
            unsafe {
                self._tab
                    .get::<EntityType>(UserEvent::VT_TARGET_TYPE, Some(EntityType::stream_profile))
                    .unwrap()
            }
        }
        #[inline]
        pub fn source_id(&self) -> Option<flatbuffers::Vector<'a, u8>> {
            // Safety:
            // Created from valid Table for this object
            // which contains a valid value in this slot
            unsafe {
                self._tab
                    .get::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'a, u8>>>(
                        UserEvent::VT_SOURCE_ID,
                        None,
                    )
            }
        }
        #[inline]
        pub fn target_id(&self) -> Option<flatbuffers::Vector<'a, u8>> {
            // Safety:
            // Created from valid Table for this object
            // which contains a valid value in this slot
            unsafe {
                self._tab
                    .get::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'a, u8>>>(
                        UserEvent::VT_TARGET_ID,
                        None,
                    )
            }
        }
        #[inline]
        pub fn timestamp(&self) -> u64 {
            // Safety:
            // Created from valid Table for this object
            // which contains a valid value in this slot
            unsafe {
                self._tab
                    .get::<u64>(UserEvent::VT_TIMESTAMP, Some(0))
                    .unwrap()
            }
        }
        #[inline]
        pub fn status(&self) -> ActionStatus {
            // Safety:
            // Created from valid Table for this object
            // which contains a valid value in this slot
            unsafe {
                self._tab
                    .get::<ActionStatus>(UserEvent::VT_STATUS, Some(ActionStatus::preparing))
                    .unwrap()
            }
        }
    }

    impl flatbuffers::Verifiable for UserEvent<'_> {
        #[inline]
        fn run_verifier(
          v: &mut flatbuffers::Verifier,
          pos: usize,
        ) -> Result<(), flatbuffers::InvalidFlatbuffer> {
          v.visit_table(pos)?
                .visit_field::<EntityType>("source_type", Self::VT_SOURCE_TYPE, false)?
                .visit_field::<EntityType>("target_type", Self::VT_TARGET_TYPE, false)?
                .visit_field::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'_, u8>>>(
                    "source_id",
                    Self::VT_SOURCE_ID,
                    false,
                )?
                .visit_field::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'_, u8>>>(
                    "target_id",
                    Self::VT_TARGET_ID,
                    false,
                )?
                .visit_field::<u64>("timestamp", Self::VT_TIMESTAMP, false)?
                .visit_field::<ActionStatus>("status", Self::VT_STATUS, false)?
                .finish();
            Ok(())
        }
    }
    pub struct UserEventArgs<'a> {
        pub source_type: EntityType,
        pub target_type: EntityType,
        pub source_id: Option<flatbuffers::WIPOffset<flatbuffers::Vector<'a, u8>>>,
        pub target_id: Option<flatbuffers::WIPOffset<flatbuffers::Vector<'a, u8>>>,
        pub timestamp: u64,
        pub status: ActionStatus,
    }
    impl<'a> Default for UserEventArgs<'a> {
        #[inline]
        fn default() -> Self {
            UserEventArgs {
                source_type: EntityType::stream_profile,
                target_type: EntityType::stream_profile,
                source_id: None,
                target_id: None,
                timestamp: 0,
                status: ActionStatus::preparing,
            }
        }
    }

    pub struct UserEventBuilder<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> {
        fbb_: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
        start_: flatbuffers::WIPOffset<flatbuffers::TableUnfinishedWIPOffset>,
    }
    impl<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> UserEventBuilder<'a, 'b, A> {
        #[inline]
        pub fn add_source_type(&mut self, source_type: EntityType) {
            self.fbb_.push_slot::<EntityType>(
                UserEvent::VT_SOURCE_TYPE,
                source_type,
                EntityType::stream_profile,
            );
        }
        #[inline]
        pub fn add_target_type(&mut self, target_type: EntityType) {
            self.fbb_.push_slot::<EntityType>(
                UserEvent::VT_TARGET_TYPE,
                target_type,
                EntityType::stream_profile,
            );
        }
        #[inline]
        pub fn add_source_id(
            &mut self,
            source_id: flatbuffers::WIPOffset<flatbuffers::Vector<'b, u8>>,
        ) {
            self.fbb_
                .push_slot_always::<flatbuffers::WIPOffset<_>>(UserEvent::VT_SOURCE_ID, source_id);
        }
        #[inline]
        pub fn add_target_id(
            &mut self,
            target_id: flatbuffers::WIPOffset<flatbuffers::Vector<'b, u8>>,
        ) {
            self.fbb_
                .push_slot_always::<flatbuffers::WIPOffset<_>>(UserEvent::VT_TARGET_ID, target_id);
        }
        #[inline]
        pub fn add_timestamp(&mut self, timestamp: u64) {
            self.fbb_
                .push_slot::<u64>(UserEvent::VT_TIMESTAMP, timestamp, 0);
        }
        #[inline]
        pub fn add_status(&mut self, status: ActionStatus) {
            self.fbb_.push_slot::<ActionStatus>(
                UserEvent::VT_STATUS,
                status,
                ActionStatus::preparing,
            );
        }
        #[inline]
        pub fn new(
            _fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
        ) -> UserEventBuilder<'a, 'b, A> {
            let start = _fbb.start_table();
            UserEventBuilder {
                fbb_: _fbb,
                start_: start,
            }
        }
        #[inline]
        pub fn finish(self) -> flatbuffers::WIPOffset<UserEvent<'a>> {
            let o = self.fbb_.end_table(self.start_);
            flatbuffers::WIPOffset::new(o.value())
        }
    }

    impl core::fmt::Debug for UserEvent<'_> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let mut ds = f.debug_struct("UserEvent");
            ds.field("source_type", &self.source_type());
            ds.field("target_type", &self.target_type());
            ds.field("source_id", &self.source_id());
            ds.field("target_id", &self.target_id());
            ds.field("timestamp", &self.timestamp());
            ds.field("status", &self.status());
            ds.finish()
        }
    }
    #[inline]
    /// Verifies that a buffer of bytes contains a `Event`
    /// and returns it.
    /// Note that verification is still experimental and may not
    /// catch every error, or be maximally performant. For the
    /// previous, unchecked, behavior use
    /// `root_as_event_unchecked`.
    pub fn root_as_event(buf: &[u8]) -> Result<Event, flatbuffers::InvalidFlatbuffer> {
        flatbuffers::root::<Event>(buf)
    }
    #[inline]
    /// Verifies that a buffer of bytes contains a size prefixed
    /// `Event` and returns it.
    /// Note that verification is still experimental and may not
    /// catch every error, or be maximally performant. For the
    /// previous, unchecked, behavior use
    /// `size_prefixed_root_as_event_unchecked`.
    pub fn size_prefixed_root_as_event(
        buf: &[u8],
    ) -> Result<Event, flatbuffers::InvalidFlatbuffer> {
        flatbuffers::size_prefixed_root::<Event>(buf)
    }
    #[inline]
    /// Verifies, with the given options, that a buffer of bytes
    /// contains a `Event` and returns it.
    /// Note that verification is still experimental and may not
    /// catch every error, or be maximally performant. For the
    /// previous, unchecked, behavior use
    /// `root_as_event_unchecked`.
    pub fn root_as_event_with_opts<'b, 'o>(
        opts: &'o flatbuffers::VerifierOptions,
        buf: &'b [u8],
    ) -> Result<Event<'b>, flatbuffers::InvalidFlatbuffer> {
        flatbuffers::root_with_opts::<Event<'b>>(opts, buf)
    }
    #[inline]
    /// Verifies, with the given verifier options, that a buffer of
    /// bytes contains a size prefixed `Event` and returns
    /// it. Note that verification is still experimental and may not
    /// catch every error, or be maximally performant. For the
    /// previous, unchecked, behavior use
    /// `root_as_event_unchecked`.
    pub fn size_prefixed_root_as_event_with_opts<'b, 'o>(
        opts: &'o flatbuffers::VerifierOptions,
        buf: &'b [u8],
    ) -> Result<Event<'b>, flatbuffers::InvalidFlatbuffer> {
        flatbuffers::size_prefixed_root_with_opts::<Event<'b>>(opts, buf)
    }
    #[inline]
    /// Assumes, without verification, that a buffer of bytes contains a Event and returns it.
    /// # Safety
    /// Callers must trust the given bytes do indeed contain a valid `Event`.
    pub unsafe fn root_as_event_unchecked(buf: &[u8]) -> Event {
        flatbuffers::root_unchecked::<Event>(buf)
    }
    #[inline]
    /// Assumes, without verification, that a buffer of bytes contains a size prefixed Event and returns it.
    /// # Safety
    /// Callers must trust the given bytes do indeed contain a valid size prefixed `Event`.
    pub unsafe fn size_prefixed_root_as_event_unchecked(buf: &[u8]) -> Event {
        flatbuffers::size_prefixed_root_unchecked::<Event>(buf)
    }
    #[inline]
    pub fn finish_event_buffer<'a, 'b, A: flatbuffers::Allocator + 'a>(
        fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
        root: flatbuffers::WIPOffset<Event<'a>>,
    ) {
        fbb.finish(root, None);
    }

    #[inline]
    pub fn finish_size_prefixed_event_buffer<'a, 'b, A: flatbuffers::Allocator + 'a>(
        fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
        root: flatbuffers::WIPOffset<Event<'a>>,
    ) {
        fbb.finish_size_prefixed(root, None);
    }
} // pub mod Arkavo