//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use std::cell::RefCell;
type LogFormat = RefCell<Box< dyn Fn(u32, &str) -> String + Send + Sync>>;
thread_local! {pub static LOG_FORMAT: LogFormat = RefCell::new(Box::new(|_line, _file| { String::new() }))}

/// Creates and prints an error to be logged.
///
/// Output is logged to stderr.
///
/// Will print in both release and debug mode.
///
/// Log format can be overridden in `logInitCustom`
#[macro_export]
macro_rules! fpsLogError {
    ($errorCode: expr, $($arg:tt)+) => {
        let errorMessage = format!($($arg)+);
        let string = format!("{},FP_ERRCODE=\"{}\",{}",
                              $crate::logging::LOG_FORMAT.with( |a| {
                                  a.borrow()(line!(), file!())
                              }), $errorCode, errorMessage);
        eprintln!("{}", string);
    };

    ($errorCode: expr) => {
        let string = format!("{} FP_ERRCODE=\"{}\", {}",
                              $crate::logging::LOG_FORMAT.with( |a| {
                                  a.borrow()(line!(), file!())
                              }), $errorCode);
        eprintln!("{}", string);
    };
}
