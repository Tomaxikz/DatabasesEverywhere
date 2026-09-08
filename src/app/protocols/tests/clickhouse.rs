use crate::protocols::clickhouse;

#[test]
fn http_routing_accepts_official_headers_query_parameters_and_basic_auth() {
    let headers = clickhouse::parse_http_initial_route(
        b"POST /?query=SELECT+1 HTTP/1.1\r\nX-ClickHouse-User: tenant\r\nX-ClickHouse-Database: app\r\n\r\n",
    )
    .unwrap();
    assert_eq!(headers.username, "tenant");
    assert_eq!(headers.database, "app");

    let query = clickhouse::parse_http_initial_route(
        b"GET /?user=tenant&database=app&query=SELECT+1 HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .unwrap();
    assert_eq!(query, headers);

    let basic = clickhouse::parse_http_initial_route(
        b"GET /?database=app HTTP/1.1\r\nAuthorization: Basic dGVuYW50OnNlY3JldA==\r\n\r\n",
    )
    .unwrap();
    assert_eq!(basic, headers);
}

#[test]
fn http_routing_rejects_conflicting_tenant_selectors() {
    for request in [
        "GET /?user=a&user=b HTTP/1.1\r\n\r\n",
        "GET /?user=a&%75ser=b HTTP/1.1\r\n\r\n",
        "GET /?user=a HTTP/1.1\r\nX-ClickHouse-User: b\r\n\r\n",
        "GET /?user=a&database=a&database=b HTTP/1.1\r\n\r\n",
        "GET /?user=a&database=a HTTP/1.1\r\nX-ClickHouse-Database: b\r\n\r\n",
        "GET / HTTP/1.1\r\nX-ClickHouse-User: a\r\nAuthorization: Basic YjpzZWNyZXQ=\r\n\r\n",
        "GET / HTTP/1.1\r\nAuthorization: Basic YjpzZWNyZXQ=\r\nX-ClickHouse-User: a\r\n\r\n",
    ] {
        assert!(
            clickhouse::parse_http_initial_route(request.as_bytes()).is_err(),
            "{request}"
        );
    }
    let route = clickhouse::parse_http_initial_route(
        b"GET /?user=b&database=app HTTP/1.1\r\nX-ClickHouse-User: b\r\nX-ClickHouse-Database: app\r\nAuthorization: Basic YjpzZWNyZXQ=\r\n\r\n"
    ).unwrap();
    assert_eq!(route.username, "b");
    assert_eq!(route.database, "app");
}
