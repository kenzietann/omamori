# Real logs of web frameworks

Logs written by real applications of fifteen setups of backend frameworks during one attack, made with
[`../../applab`](../../applab) on 2026-11-13. Each folder has the json-file log of Docker (`docker-json.log`),
the same log from `docker logs --timestamps` (`docker-timestamps.log`), and for Spring Boot and Laravel their
own log files. [`expected.json`](expected.json) lists the rules that must fire on each file; the test
`TestRealLogsOfTheFrameworks` reads every file and checks that every line is read and exactly these rules fire.

The attacker was a container at a private lab address. The passwords of the attack are not in any log.
See [docs/apps.md](../../../docs/apps.md) for what each setup shows and why some show less.
