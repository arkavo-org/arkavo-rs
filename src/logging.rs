//! Log macros that survive a compile-time `log` level cut-off.
//!
//! The vendored FairPlay SDK enables the `log` crate's `release_max_level_off`
//! feature, and Cargo unifies features across the build, so in a release build with
//! `fairplay` every `log::info!`, `warn!` and `error!` compiles to nothing. These
//! macros take the same arguments but hand the record straight to the installed
//! logger (env_logger), which applies `RUST_LOG` at run time. Use them instead of the
//! `log` crate's macros: `use nanotdf::{info, warn}` in the binary, `crate::` in the
//! library.

#[doc(hidden)]
pub fn __log(
    level: log::Level,
    target: &str,
    args: std::fmt::Arguments,
    file: &'static str,
    line: u32,
) {
    let logger = log::logger();
    let metadata = log::Metadata::builder().level(level).target(target).build();
    if logger.enabled(&metadata) {
        logger.log(
            &log::Record::builder()
                .metadata(metadata)
                .args(args)
                .module_path(Some(target))
                .file_static(Some(file))
                .line(Some(line))
                .build(),
        );
    }
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => {
        $crate::logging::__log(::log::Level::Error, module_path!(), format_args!($($arg)+), file!(), line!())
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => {
        $crate::logging::__log(::log::Level::Warn, module_path!(), format_args!($($arg)+), file!(), line!())
    };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => {
        $crate::logging::__log(::log::Level::Info, module_path!(), format_args!($($arg)+), file!(), line!())
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => {
        $crate::logging::__log(::log::Level::Debug, module_path!(), format_args!($($arg)+), file!(), line!())
    };
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)+) => {
        $crate::logging::__log(::log::Level::Trace, module_path!(), format_args!($($arg)+), file!(), line!())
    };
}
