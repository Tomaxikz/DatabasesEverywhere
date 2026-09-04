use bson::{Binary, Bson, doc, spec::BinarySubtype};

use crate::protocols::mongodb::{self, MongoMessage};

#[test]
fn capability_hello_is_route_free_but_speculative_scram_routes() {
    let negotiated = MongoMessage {
        request_id: 1,
        op_code: 2013,
        body: Some(doc! {
            "hello": 1_i32,
            "saslSupportedMechs": "tenant_db.tenant_user",
        }),
        raw: Vec::new(),
    };
    let speculative = MongoMessage {
        request_id: 2,
        op_code: 2013,
        body: Some(doc! {
            "isMaster": 1_i32,
            "speculativeAuthenticate": {
                "saslStart": 1_i32,
                "mechanism": "SCRAM-SHA-256",
                "payload": Bson::Binary(Binary {
                    subtype: BinarySubtype::Generic,
                    bytes: b"n,,n=tenant_user,r=driverNonce".to_vec(),
                }),
                "db": "tenant_db",
            },
        }),
        raw: Vec::new(),
    };
    assert!(
        mongodb::parse_hello_speculative_route(&negotiated)
            .unwrap()
            .is_none()
    );
    let route = mongodb::parse_hello_speculative_route(&speculative)
        .unwrap()
        .unwrap();
    assert_eq!(route.username, "tenant_user");
    assert_eq!(route.database, "tenant_db");
}

#[test]
fn synthetic_hello_is_a_standalone_uncompressed_common_denominator() {
    let request = MongoMessage {
        request_id: 1,
        op_code: 2013,
        body: Some(doc! {
            "hello": 1_i32,
            "saslSupportedMechs": "tenant_db.tenant_user",
        }),
        raw: Vec::new(),
    };
    let hello = mongodb::hello_response(&request);
    assert_eq!(
        hello.get_i32("maxMessageSizeBytes").unwrap(),
        mongodb::MAX_WIRE_MESSAGE_BYTES as i32
    );
    assert_eq!(hello.get_i32("maxWireVersion").unwrap(), 21);
    assert_eq!(hello.get_i32("minWireVersion").unwrap(), 0);
    assert!(hello.get_array("compression").unwrap().is_empty());
    assert!(hello.get_bool("isWritablePrimary").unwrap());
    assert!(hello.get("setName").is_none());
    assert!(hello.get("hosts").is_none());
    assert_eq!(
        hello.get_array("saslSupportedMechs").unwrap(),
        &vec![
            Bson::String("SCRAM-SHA-1".to_string()),
            Bson::String("SCRAM-SHA-256".to_string())
        ]
    );
}

#[test]
fn speculative_scram_ignores_untrusted_capability_identity() {
    let message = MongoMessage {
        request_id: 3,
        op_code: 2013,
        body: Some(doc! {
            "hello": 1_i32,
            "saslSupportedMechs": "one_db.one_user",
            "speculativeAuthenticate": {
                "saslStart": 1_i32,
                "mechanism": "SCRAM-SHA-1",
                "payload": Bson::Binary(Binary {
                    subtype: BinarySubtype::Generic,
                    bytes: b"n,,n=two_user,r=nonce".to_vec(),
                }),
                "db": "two_db",
            },
        }),
        raw: Vec::new(),
    };
    let route = mongodb::parse_hello_speculative_route(&message)
        .unwrap()
        .unwrap();
    assert_eq!(route.username, "two_user");
    assert_eq!(route.database, "two_db");

    let unsafe_name = MongoMessage {
        request_id: 4,
        op_code: 2013,
        body: Some(doc! { "hello": 1_i32, "saslSupportedMechs": "admin.bad.user" }),
        raw: Vec::new(),
    };
    assert!(
        mongodb::parse_hello_speculative_route(&unsafe_name)
            .unwrap()
            .is_none()
    );
}
