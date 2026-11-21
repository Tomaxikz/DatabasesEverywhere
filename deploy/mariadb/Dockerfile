FROM scratch AS source
ADD --checksum=sha256:75aae4d48df905734e24a85b955bbcdc43f4b122b450bc4ad2bc92f5d1ac578d https://archive.mariadb.org/mariadb-12.3.4/source/mariadb-12.3.4.tar.gz /mariadb.tar.gz

FROM mariadb:12.3.2@sha256:a02fe89cb597d4375812b2eac90cf9d0775d4686daa7f7cc750ebbcad7525bbc AS base

FROM base AS build
RUN rm /etc/apt/sources.list.d/mariadb.list && apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      bison build-essential cmake libaio-dev libcurl4-openssl-dev libevent-dev \
      libjemalloc-dev libkrb5-dev liblz4-dev liblzma-dev libncurses-dev \
      libpcre2-dev libssl-dev libsystemd-dev liburing-dev libxml2-dev libzstd-dev \
      ninja-build patch pkg-config zlib1g-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN --mount=from=source,source=/mariadb.tar.gz,target=/tmp/mariadb.tar.gz \
    echo '75aae4d48df905734e24a85b955bbcdc43f4b122b450bc4ad2bc92f5d1ac578d  /tmp/mariadb.tar.gz' | sha256sum --check && \
    tar -xzf /tmp/mariadb.tar.gz --strip-components=1
COPY innodb-blob-reservation.patch /tmp/innodb.patch
RUN patch --fuzz=0 -p1 < /tmp/innodb.patch
ARG BUILD_JOBS=4
RUN cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/usr -DINSTALL_LAYOUT=DEB -DINSTALL_SYSCONFDIR=/etc/mysql \
      -DMYSQL_DATADIR=/var/lib/mysql -DMYSQL_UNIX_ADDR=/run/mysqld/mysqld.sock \
      "-DCMAKE_C_FLAGS_RELEASE=-O2 -DNDEBUG" "-DCMAKE_CXX_FLAGS_RELEASE=-O2 -DNDEBUG" \
      -DWITH_WSREP=ON -DWITH_SSL=system -DWITH_UNIT_TESTS=OFF -DWITH_EMBEDDED_SERVER=OFF \
      -DPLUGIN_AWS_KEY_MANAGEMENT=NO -DPLUGIN_COLUMNSTORE=NO -DPLUGIN_CONNECT=NO \
      -DPLUGIN_MROONGA=NO -DPLUGIN_ROCKSDB=NO -DPLUGIN_SPIDER=NO && \
    cmake --build /build --parallel "${BUILD_JOBS}" --target mariadbd

FROM base
# Package installation initializes a temporary database. Discard it so the
# entrypoint bootstraps each new volume with its configured credentials.
RUN --mount=type=tmpfs,target=/var/lib/mysql \
    sed -i 's|http://archive.mariadb.org/mariadb-12.3.2|https://archive.mariadb.org/mariadb-12.3.4|' /etc/apt/sources.list.d/mariadb.list && \
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::=--force-confold \
      install --yes --no-install-recommends mariadb-server mariadb-server-core mariadb-server-galera \
      mariadb-client mariadb-client-core mariadb-backup && \
    mariadbd --version | grep -F '12.3.4-MariaDB' && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/sql/mariadbd /usr/sbin/mariadbd
RUN test -z "$(ls -A /var/lib/mysql)" && mariadbd --version
