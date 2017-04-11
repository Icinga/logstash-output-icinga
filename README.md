# Icinga Logstash Plugin

This is a plugin for [Logstash](https://github.com/elastic/logstash). It calls the Icinga 2 API to perform various
actions.

## Installation

```shell
/usr/share/logstash/bin/logstash-plugin install logstash-output-icinga-0.1.0.gem
```

## Configuration
This plugin supports the following parameters:

| Parameter        | Type     | Default    | Required |
|:-----------------|:---------|:-----------|:---------|
| `host`           | string   | -          | Yes      |
| `port`           | number   | `5665`     | No       |
| `user`           | string   | -          | Yes      |
| `password`       | passowrd | -          | Yes      |
| `ssl_verify`     | boolean  | `true`     | No       |
| `action`         | string   | -          | Yes      |
| `action_config`  | hash     | -          | Yes      |
| `icinga_host`    | string   | -          | Yes      |
| `icinga_service` | string   | -          | Yes      |

Following options are available for the `action` parameter:

* `process-check-result`
* `send-custom-notification`
* `add-comment`
* `remove-comment`
* `schedule-downtime`
* `remove-downtime`

Each `action` has its own settings for `action_config`. Possible options are listed in the 
[Icinga documentation](https://docs.icinga.com/icinga2/latest/doc/module/icinga2/chapter/icinga2-api#icinga2-api-actions).