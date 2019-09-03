# L2 MitM Attack

**Author:** Peter Gazdík

The man-in-the-middle attack on the data layer.	

## Build

```
$ cmake .
$ make
```

## Run

### Scanner

```
./pds-scanner -i interface -f file
```

### Spoof

```
./pds-spoof -i interface -t sec -p protocol -victim1ip ipaddress -victim1mac macaddress -victim2ip ipaddress -victim2mac macaddress 
```

### Intercept

```
./pds-intercept -i interface -f file
```

