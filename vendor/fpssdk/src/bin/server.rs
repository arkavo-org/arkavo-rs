//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use std::ffi::{c_char, CString};
use std::{
    io::{Read, Write, BufReader, prelude::*},
    net::{TcpListener, TcpStream},
};

use fpssdk::base::structures::base_fps_structures::Base;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();

    Base::logInit();
    if Base::readCertificates().is_err() {
        return;
    }

    for stream in listener.incoming() {
        let stream = stream.unwrap();

        handle_connection(stream);
    }
}

fn handle_connection(mut stream: TcpStream) {
    let mut buf_reader = BufReader::new(&stream);
    let mut content_length = 0;

    // Read request line
    let mut request_line: String = String::default();
    let bytes_read = buf_reader.read_line(&mut request_line).unwrap_or_default();
    let mut method: &str = "";
    let mut endpoint: &str = "";
    if bytes_read > 0 {
        let mut r = request_line.split(' ');
        method = r.next().unwrap();
        endpoint = r.next().unwrap();
    }

    // Read headers
    for line in buf_reader.by_ref().lines() {
        let line = line.unwrap();
        if line.is_empty() {
            break; // Empty line = end of headers
        }
        if let Some(cl) = line.strip_prefix("Content-Length: ") {
            content_length = cl.parse::<usize>().unwrap_or(0);
        }
    }

    // Read exactly Content-Length bytes for the body
    let mut raw_body = vec![0; content_length];
    if content_length > 0 {
        buf_reader.read_exact(&mut raw_body).unwrap();
    }

    let content;

    if endpoint == "/fps/v" {
        // Handle version request
        unsafe {
            let mut sdk_version: *mut c_char = std::ptr::null_mut();

            fpssdk::fpsGetVersion(&mut sdk_version);

            let result_cstring = CString::from_raw(sdk_version);
            content = result_cstring.into_string().unwrap_or_default();
        }
    } else {
        // Handle license request

        // Only allow POST method
        if method != "POST" {
            let status_line = "HTTP/1.1 405 Method Not Allowed";
            let response = format!("{status_line}\r\nContent-Length: 0\r\n\r\n");
            stream.write_all(response.as_bytes()).unwrap();
            return;
        }

        let body = String::from_utf8(raw_body).unwrap();

        let len = body.len();
        unsafe {
            let body_cstring = CString::new(body).unwrap_or_default().into_raw();
            let mut out_body: *mut c_char = std::ptr::null_mut();
            let mut out_body_length: usize = 0;

            // Call library to generate the output JSON
            fpssdk::fpsProcessOperations(body_cstring, len, &mut out_body, &mut out_body_length);
            let result_cstring = CString::from_raw(out_body);
            content = result_cstring.into_string().unwrap_or_default();
        }
    }

    // Construct response
    let status_line = "HTTP/1.1 200 OK";
    let length = content.len();

    let response = format!("{status_line}\r\nContent-Length: {length}\r\n\r\n{content}");

    stream.write_all(response.as_bytes()).unwrap();
}
