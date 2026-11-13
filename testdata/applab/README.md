# Lab applications

Small applications of the most used backend frameworks, each with a login API and an endpoint that reaches a
database, logging the way that framework does by default or most commonly. They made the real logs in
[`../fixtures/apps`](../fixtures/apps). Nothing here is part of Omamori itself.

```sh
./build.sh                 # builds omamori-applab-<name> images (Docker; downloads each framework once)
./run.sh express           # runs one app on a network with no way out, attacks it, writes out/express/
./run.sh gin gin           # the Go image takes the framework as its argument: gin, echo or chi
OM=omamori ./score.sh express gin
```

`run.sh` starts the app and the attacker of `omamori lab` (`omamori-lab-attacker:1`; run `omamori lab` once to
build it) on an `--internal` Docker network, runs [`attack.sh`](attack.sh), and copies out the json-file log of
Docker (through `colima ssh`; on Docker Desktop or Engine, read `/var/lib/docker/containers/<id>/<id>-json.log`
directly), `docker logs --timestamps`, and the log files of Spring Boot (Tomcat) and Laravel. All addresses are
private lab addresses, and the attack reaches only the app.
