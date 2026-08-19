use bson::{Binary, Bson, doc, spec::BinarySubtype};

use crate::protocols::mongodb::{self, MongoMessage, MongodbProxyError};

#[test]
fn current_java_node_and_python_hello_shapes_resolve_the_same_route() {
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
    for message in [negotiated, speculative] {
        let routes = mongodb::parse_hello_routes(&message).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].username, "tenant_user");
        assert_eq!(routes[0].database, "tenant_db");
    }
}

#[test]
fn synthetic_hello_is_a_standalone_uncompressed_common_denominator() {
    let hello = mongodb::hello_response();
    assert_eq!(hello.get_i32("maxWireVersion").unwrap(), 21);
    assert_eq!(hello.get_i32("minWireVersion").unwrap(), 0);
    assert!(hello.get_array("compression").unwrap().is_empty());
    assert!(hello.get_bool("isWritablePrimary").unwrap());
    assert!(hello.get("setName").is_none());
    assert!(hello.get("hosts").is_none());
}

#[test]
fn conflicting_driver_route_hints_fail_closed() {
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
    let routes = mongodb::parse_hello_routes(&message).unwrap();
    assert_eq!(routes.len(), 2);
    assert_ne!(routes[0], routes[1]);

    let unsafe_name = MongoMessage {
        request_id: 4,
        op_code: 2013,
        body: Some(doc! { "hello": 1_i32, "saslSupportedMechs": "admin.bad.user" }),
        raw: Vec::new(),
    };
    assert!(matches!(
        mongodb::parse_hello_routes(&unsafe_name),
        Err(MongodbProxyError::InvalidHelloRoute)
    ));
}
