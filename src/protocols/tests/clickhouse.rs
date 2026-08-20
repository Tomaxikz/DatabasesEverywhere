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
