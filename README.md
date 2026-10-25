# DatabasesEverywhere

Databases Everywhere (Called dbev shortly) is a Rust based linux daemon used to manage various database types in isolated environments with resource limits (Either podman or docker). 

Containers run in **network_mode: none** which gives no real network to the containers, however the gateway connects to these containers via unix sockets and routes the requests to them. Therefore this allows exposing all databases under single port per protocol.

## Install

Dbev requires you to have either **Docker** or **Podman** installed. If you dont have please find according documentation for installing them on your system

### Downloading dbev

Commands bellow pull the latest github release to your machine and gives the binary the proper execution permissions.

```bash
sudo curl -fL "https://github.com/Tomaxikz/DatabasesEverywhere/releases/latest/download/dbev-$(uname -m | sed 's/^aarch64$/arm64/; s/^amd64$/x86_64/')-linux" -o /usr/local/bin/dbev &&
sudo chmod +x /usr/local/bin/dbev
```

### Creating a config file

Dbev requies a **config.yml** to be located at `/etc/databases-everywhere/config.yml` or for docker compose installations `dir/config/config.yml`. 

### Setting up databases everywhere

The commands bellow setup all the directories with proper permissions and linux service and checks the status of the service.

```bash
sudo dbev --setup
sudo journalctl -u databases-everywhere -f
```

## Documentation

Documentation is currently in process of rewriting please stand by for v1 release of the dbev to get proper documentation.

## Features

Dbev has came a long way over the last months and has gained quite few features. If you care you can read about them bellow.

### Supported databases

| Database   | Dedicated | Shared |
| ---------- | --------- | ------ |
| PostgreSQL | Yes       | Yes    |
| MySQL      | Yes       | Yes    |
| MariaDB    | Yes       | Yes    |
| MongoDB    | Yes       | Yes    |
| ClickHouse | Yes       | Yes    |
| Redis      | Yes       | No     |
| Valkey     | Yes       | No     |
| Qdrant     | Yes       | No     |

#### What does `Dedicated` or `Shared` mean?

Dbev implemented a new system of databases creating few releases back. 

**Dedicated** Means each database create is created as a new container with its own dedicated cpu memory and disk resources. This is great but downside is that this creates a new process each time which by default consumes more memory per new database created.

**Shared** also creates a container, but that container (a pool) can host many tenant databases inside it. The tenants share the pool's CPU and memory, but each one still has its own login, its own data and its own disk limit. You set the pool's CPU, memory and disk when you create the pool, the same way you would for a dedicated database, and then create databases inside it.

The tenant disk limits all have to fit inside the pool's disk, so one database filling up its limit doesn't stop the others from saving data. On PostgreSQL, MySQL and MariaDB with XFS, ext4 or F2FS the limits are hard. Anywhere else dbev checks usage and stops the database once it hits its limit, so it can go a bit over before that happens.

## Supported engines

| Engine  | Support 
| ---------- | --------- | 
| Docker | Yes       | 
| Podman     | Nearly as tested as docker       | 
| Systemd services    | Planned       |
