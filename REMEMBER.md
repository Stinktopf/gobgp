# Zero to GoBGP

## Docker

Build and start two connected GoBGP routers:

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

## Inject Route in Router A

```bash
sudo docker exec -it gobgp_1 gobgp global rib add 203.0.113.0/24 nexthop 10.0.0.254 identifier 1
sudo docker exec -it gobgp_1 gobgp global rib add 203.0.113.0/24 nexthop 10.0.0.254 aspath 64000 community 64000:100
sudo docker exec -it gobgp_1 gobgp global rib add 203.0.113.0/24 nexthop 10.0.0.254 aspath 64500 identifier 1
```

## Show RIB on Both Routers

```bash
sudo docker exec -it gobgp_1 gobgp global rib
sudo docker exec -it gobgp_2 gobgp global rib
sudo docker exec -it gobgp_3 gobgp global rib
sudo docker exec -it gobgp_4 gobgp global rib
```

One can observe that the **HIGH-BANDWITH** and **STANDARD** routes come over **R2** and **LOW-LATENCY** routes come over **R3** to **R4**.

## Adjust Route in Router A

```bash
sudo docker exec -it gobgp_1 gobgp global rib add 203.0.113.0/24 nexthop 10.0.0.254 aspath 64500 identifier 1
```

One can observe that the **HIGH-BANDWITH** route comes over R2 and **LOW-LATENCY** and **STANDARD** routes come over **R3** to **R4**.

## Clear RIB

```bash
sudo docker exec -it gobgp_1 gobgp global rib -a ipv4 del all
sudo docker exec -it gobgp_2 gobgp global rib -a ipv4 del all
sudo docker exec -it gobgp_3 gobgp global rib -a ipv4 del all
sudo docker exec -it gobgp_4 gobgp global rib -a ipv4 del all
```
