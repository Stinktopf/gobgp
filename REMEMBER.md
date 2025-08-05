# Zero to GoBGP

## Build and Compile

Install Go and compile GoBGP with OPERA support:

```bash
sudo snap install go --classic
go mod download
go build cmd/gobgp
go build cmd/gobgpd
```

## Enable OPERA Mode

Activate OPERA path selection via environment:

```bash
export GOBGP_OPERA_ENABLED=true
```

## Local Daemon Test

Start GoBGP with a local config:

```bash
sudo -E ./gobgpd -f conf1.conf
```

Inject multiple paths for testing:

```bash
./gobgp global rib add 203.0.113.0/24 nexthop 10.0.255.254 aspath 65001,65001,65001 identifier 1
./gobgp global rib add 203.0.113.0/24 nexthop 10.0.255.254 aspath 65001,65001 identifier 2
./gobgp global rib add 203.0.113.0/24 nexthop 10.0.255.254 aspath 65001,65000 identifier 3
./gobgp global rib add 203.0.113.0/24 nexthop 10.0.255.254 aspath 65001,65002 identifier 4
./gobgp global rib add 203.0.113.0/24 nexthop 10.0.255.254 aspath 65001 identifier 5
./gobgp global rib add 203.0.113.0/24 nexthop 10.0.255.254 aspath 65000 identifier 6
./gobgp global rib add 203.0.113.0/24 nexthop 10.0.255.254 aspath 64999
```

Show RIB:
```bash
./gobgp global rib
```

## Docker Setup

Build and start two connected GoBGP routers:

```bash
sudo docker-compose build
sudo docker-compose up -d
```

## Check BGP Session

Ensure both routers establish a connection:

```bash
sudo docker exec -it gobgp_1 gobgp neighbor
sudo docker exec -it gobgp_2 gobgp neighbor
```

## Inject Route in Router A

Inject a route into Router A and verify propagation to Router B:

```bash
sudo docker exec -it gobgp_1 gobgp global rib add 203.0.113.0/24 nexthop 10.0.0.254 aspath 65001,65000
sudo docker exec -it gobgp_1 gobgp global rib
sudo docker exec -it gobgp_2 gobgp global rib
sudo docker exec -it gobgp_1 gobgp global rib add 203.0.113.0/24 nexthop 10.0.0.254 aspath 65001,65000,64999 identifier 2```

## Show RIB on Both Routers

```bash
sudo docker exec -it gobgp_1 gobgp global rib
sudo docker exec -it gobgp_2 gobgp global rib
```

Only the best route (based on OPERA path selection logic) is propagated.

## Clear RIB

```bash
sudo docker exec -it gobgp_1 gobgp global rib -a ipv4 del all
sudo docker exec -it gobgp_2 gobgp global rib -a ipv4 del all
```
