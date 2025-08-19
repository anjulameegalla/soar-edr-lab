# Integration of SOAR and EDR featuring LimaCharlie and Tines

## Playbook workflow

![diagram.png](diagram.png)

## Azure VM

- Resource group : SOAR-EDR-Lab
- VM name : GOTHAM-DC
- VM type : B2s General Purpose
- Image : Windows Server 2022 Datacenter

## LaZagne - Windows security events

- Repo : https://github.com/AlessandroZ/LaZagne

## LimaCharlie config

### Installation

```bash
lc_sensor.exe -i YOUR_INSTALLATION_KEY
```

- Docs : [https://docs.limacharlie.io/docs](https://docs.limacharlie.io/docs)

![{683B2623-9FBF-4549-ACBF-675D3F643DD2}.png](683B2623-9FBF-4549-ACBF-675D3F643DD2.png)

### LimaCharlie D&R Rule

- Detect

```bash
events:
  - NEW_PROCESS
  - EXISTING_PROCESS
op: and
rules:
  - op: is windows
  - op: or
    rules:
    - case sensitive: false
      op: ends with
      path: event/FILE_PATH
      value: LaZagne.exe
    - case sensitive: false
      op: contains
      path: event/COMMAND_LINE
      value: LaZagne
    - case sensitive: false
      op: contains
      path: event/COMMAND_LINE
      value: ' all'
    - case sensitive: false
      op: is
      path: event/HASH
      value: 'dc06d62ee95062e714f2566c95b8edaabfd387023b1bf98a09078b84007d5268'
```

- Respond

```bash
- action: report
  name: detect-hacktool-lazagne
  metadata:
    author: Anon
    description: Detects the execution of LaZagne credential dumping tool via file path, command line, or file hash.
    falsepositives: 
      - Legitimate penetration testing tools named 'lazagne'
    level: high
    tags:
      - attack.credential_access
    name: HackTool - Lazagne
```

## Tines config

### Slack, Email, User prompt message structure

```html
Detection Info.

Title : <<retrieve_detections.body.cat>>
Time : <<retrieve_detections.body.detect.routing.event_time>>
Computer : <<retrieve_detections.body.detect.routing.hostname>>
Source IP : <<retrieve_detections.body.detect.routing.ext_ip>>
Username : <<retrieve_detections.body.detect.event.USER_NAME>>
File Path : <<retrieve_detections.body.detect.event.FILE_PATH>>
Command Line : <<retrieve_detections.body.detect.event.COMMAND_LINE>>
Sensor ID : <<retrieve_detections.body.detect.routing.sid>>

Detection Link : <<retrieve_detections.body.link>>
```

### Tines Storybook

![SOAR-EDR-Playbook.png](SOAR-EDR-Playbook.png)

## Demo

[https://youtu.be/8QLQ_8eqHC8](https://youtu.be/8QLQ_8eqHC8)