# Zero to GoBGP

## Install

```bash
minikube start
minikube image build -t gobgp:dev .
helm upgrade --install gobgp-lab gobgp-lab -n gobgp-lab --create-namespace
```

## See Neighbors

```bash
gobgp neighbor
```

## Add Route

```bash
gobgp global rib add 203.0.113.0/24 nexthop 10.0.0.254
gobgp global rib add 203.0.113.0/24 nexthop 10.0.0.254 aspath 64500 community 64500:200 identifier 1
```

## Monitor

```bash
gobgp monitor global rib
```

## Clear RIB

```bash
gobgp global rib -a ipv4 del all
```

## Uninstall

```bash
helm uninstall gobgp-lab -n gobgp-lab
```