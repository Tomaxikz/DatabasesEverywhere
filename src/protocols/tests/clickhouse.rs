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
fn database_rewrite_preserves_body_and_unrelated_query_parameters() {
    let request = b"POST /?query=INSERT&database=default&wait_end_of_query=1 HTTP/1.1\r\nX-ClickHouse-User: tenant\r\nContent-Length: 7\r\n\r\npayload";
    let rewritten = clickhouse::http_request_with_database(request, "tenant_db").unwrap();
    let route = clickhouse::parse_http_initial_route(&rewritten).unwrap();
    assert_eq!(route.database, "tenant_db");
    assert!(rewritten.ends_with(b"payload"));
    let text = String::from_utf8_lossy(&rewritten);
    assert!(text.contains("wait_end_of_query=1"));
    assert!(!text.contains("database=default"));
}
