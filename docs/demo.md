# Demo: one attack through three hosts

This is the walk-through of slice 7. Everything in it is synthetic: `omamori scenario --campaign`
writes the logs, and no line comes from a real system. No AI provider and no network are needed
for the steps below.

## The story

| Time | Step | Seen in | Found by |
|---|---|---|---|
| 02:10 | An outside address guesses the password of root on web01 and logs in | `web01/auth.log` | SSH login succeeded after password guessing (critical) |
| 02:14 | A new account, put into the sudo group, and a cron job that downloads a script are made on web01 | `web01/auth.log` | A new user account was made; An account was added to an admin group; Cron runs a download that is piped into a shell |
| 02:25 | web01 looks for hosts with SSH in the server network | `sensor/conn.log` (Zeek), `sensor/eve.json` (Suricata) | One internal address tries many internal addresses; Network sensor raised its highest severity |
| 02:31 | web01 guesses the password of deploy on app01 and logs in | `app01/auth.log` | SSH login succeeded after guessing from an internal address (critical) |
| 02:41 | app01 logs in to db01 with a key that was found on app01 | `db01/auth.log` | **nothing** (see below) |
| 02:52 | db01 sends 2.4 GB to an outside address | `sensor/conn.log` | Large amount of data sent to an external address |

The rest of the day has other outside addresses that scan and attack web01 (password spraying, a web
scan, injection attempts). They belong to the day of web01 and have no link to the six steps.

## Run it

```sh
omamori scenario --campaign --seed 3 --date 2026-11-10 --timezone Asia/Tokyo ./demo-campaign
omamori detect ./demo-campaign/logs --assets ./demo-campaign/assets.yml --indicators ./demo-campaign/indicators.yml \\
  --year 2026 --timezone Asia/Tokyo --store
omamori dashboard ./demo-campaign/logs
```

`detect` reads six files of three hosts and two sensors: 1,820 events, 32 rules, 22 alerts
(3 critical, 11 high, 8 medium). Without the two lists it is 20 alerts: the alert that joins the story
and the alert for the known bad address are missing. The report has one timeline for all sources. With `--store` the run
is in the local database, and the dashboard shows the alert queue with the evidence beside it.
`./demo-campaign/expected.json` holds the story, the alerts that must fire and the known misses.

`omamori scenario --campaign --benign` writes the same network on a day without the attack. It has
the things that look like the attack and are not: a monitoring host that connects to every server, a
person who goes from web01 to app01 and types a wrong password twice, a 3 GB backup to an internal
address, and a host that keeps trying one address that is gone. `detect` gives no alert for it.

For the checked AI review, add `analyze` in place of `detect` (preview first, `--yes` to send).
No recording of a review of this campaign is bundled yet.

## The asset list

```yaml
assets:
  - name: web01
    addresses: [10.0.1.10]
  - name: app01
    addresses: [10.0.2.20]
```

A name is matched with the host name in a log (also with a domain after it, and without regard to
case). An address is matched with the source and the destination of an event. Events then carry
`asset` (the machine that wrote the log), `src_asset` and `dst_asset`. A name or an address that
stands twice is refused, because one address must mean one machine. `detect`, `analyze` and `forensics`
take `--assets`, and so do their forms in the home screen; the dashboard does not take it yet.

## The indicator list

```yaml
indicators:
  - type: ip          # ip, domain or sha256
    value: 203.0.113.80
    note: where it came from
```

An event is marked when its source or destination is a listed address, when a DNS query, an HTTP host
or a TLS name is a listed domain or lies under one, when a hash field is a listed hash, or when a
command, a URL or a referrer has a listed address or name inside it. The marks are `indicator`,
`indicator_type` and `indicator_where`. One rule gives one alert for each indicator and burst.
In the campaign, 203.0.113.80 is one alert with four events from two hosts: the cron job of web01 that
downloads from it, and the upload of db01 to it. `detect`, `analyze` and `forensics` take
`--indicators`. A list with an entry that cannot be used is refused, with the number of the entry.

An event that names several indicators is marked with the first one found. Only the fields above are
searched: an address in the free text of a syslog message is not found. The list is as good as its
source: an old or wrong entry gives alerts of level high for ordinary traffic.

## What the demo must say out loud

- **Step 5 is not found.** One accepted key from an internal address looks like every ordinary login.
  Finding it needs knowledge that the rules do not have: which host normally logs in to which.
- **The two halves are joined only with the asset list.** In its own logs the first host is `web01`.
  In the logs of the other hosts and of the sensor it is `10.0.1.10`. `assets.yml` says that these are
  one machine. With it, one more critical alert fires ("A host was logged in to after password guessing
  and then guesses passwords inside", machine=web01), with its first step from `web01/auth.log` and its
  second from `app01/auth.log`, and the AI review can relate alerts through the machine. Without it,
  both halves are still found, and nothing joins them. The list is yours to keep right: a wrong or old
  entry joins the wrong machines.
- **The rules know nothing about your network.** A jump host, a vulnerability scanner of your own,
  or a backup to a cloud fires the new rules. Each needs a filter for that address.
- **Measured on synthetic days only.** Over 25 seeds: 425 of 425 expected alerts, no unexpected
  alert, and no alert on 39,397 events of days without the attack. The logs and the rules were
  written together, so this shows that the path works, not how many real intrusions would be found.
