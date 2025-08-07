# Zero to GoBGP

## Docker

Build and start four connected GoBGP routers:

```bash
sudo docker-compose up --build -d
```

## Check BGP Session

Ensure both routers establish a connection:

```bash
sudo docker exec -it gobgp_1 gobgp neighbor
sudo docker exec -it gobgp_2 gobgp neighbor
sudo docker exec -it gobgp_3 gobgp neighbor
sudo docker exec -it gobgp_4 gobgp neighbor
```

## Inject Route in Router 1

```bash
sudo docker exec -it gobgp_1 gobgp global rib add 203.0.113.0/24 nexthop 10.0.0.254 identifier 1
sudo docker exec -it gobgp_1 gobgp global rib add 203.0.113.0/24 nexthop 10.0.0.254 aspath 64000 community 64000:100
```

## Show RIB on All Routers

```bash
sudo docker exec -it gobgp_1 gobgp global rib
sudo docker exec -it gobgp_2 gobgp global rib
sudo docker exec -it gobgp_3 gobgp global rib
sudo docker exec -it gobgp_4 gobgp global rib
```


One can observe that a **HIGH-BANDWITH** route comes over R2 and a **LOW-LATENCY** and a **STANDARD** route come over **R3** to **R4**.

## Adjust Route in Router A

```bash
sudo docker exec -it gobgp_1 gobgp global rib add 203.0.113.0/24 nexthop 10.0.0.254 aspath 64500 community 64500:200 identifier 1
```

## Show RIB on All Routers

```bash
sudo docker exec -it gobgp_1 gobgp global rib
sudo docker exec -it gobgp_2 gobgp global rib
sudo docker exec -it gobgp_3 gobgp global rib
sudo docker exec -it gobgp_4 gobgp global rib
```

One can observe that a **HIGH-BANDWITH** and a **STANDARD** route come over **R2** and a **LOW-LATENCY** and a **STANDARD** route come over **R3** to **R4**.

## Clear RIB

```bash
sudo docker exec -it gobgp_1 gobgp global rib -a ipv4 del all
sudo docker exec -it gobgp_2 gobgp global rib -a ipv4 del all
sudo docker exec -it gobgp_3 gobgp global rib -a ipv4 del all
sudo docker exec -it gobgp_4 gobgp global rib -a ipv4 del all
```
