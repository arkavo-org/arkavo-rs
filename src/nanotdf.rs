#[derive(Debug)]
pub(crate) struct NanoTDF {
    version: u8,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    auth_tag: Vec<u8>,
}

impl NanoTDF {
    pub(crate) fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 1 {
            return Err("Data is too short".to_string());
        }

        let version = data[0];

        // Example lengths, modify according to actual NanoTDF specification
        let iv_length = 12;
        let auth_tag_length = 16;

        if data.len() < 1 + iv_length + auth_tag_length {
            return Err("Data is too short".to_string());
        }

        let iv = data[1..1 + iv_length].to_vec();
        let auth_tag = data[data.len() - auth_tag_length..].to_vec();
        let ciphertext = data[1 + iv_length..data.len() - auth_tag_length].to_vec();

        Ok(NanoTDF {
            version,
            iv,
            ciphertext,
            auth_tag,
        })
    }
}

#[test]
fn test_from_bytes_success() {
    let data = vec![
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32, 33,
    ];
    let result = NanoTDF::from_bytes(&data).unwrap();

    assert_eq!(result.version, 1);
    assert_eq!(result.iv, vec![2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);
    assert_eq!(result.ciphertext, vec![14, 15, 16, 17]);
    assert_eq!(
        result.auth_tag,
        vec![18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33]
    );
}

#[test]
fn test_from_bytes_fails_with_short_data() {
    let data = vec![1, 2, 3];
    let result = NanoTDF::from_bytes(&data);

    assert!(result.is_err());
}

#[test]
fn test_from_bytes_fails_with_no_data() {
    let data = vec![];
    let result = NanoTDF::from_bytes(&data);

    assert!(result.is_err());
}
