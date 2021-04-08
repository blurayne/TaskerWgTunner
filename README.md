# Tasker WireGuard Tunnel Automation

## About

Helper to Automate spinning up and shutting down WireGuard tunnel via Tasker Automation (or compatible API)

## Usage

This section needs to be updated. I use a [MacroDroid](https://www.macrodroid.com/) with Android QuickTile and with following config.

##### App Intend Config

`````net.evolution515.taskerwgtunnel/.MainActivity%IntentReceiver
net.evolution515.taskerwgtunnel/.MainActivity$IntentReceiver
`````

````
com.wireguard.android.action.SET_TUNNEL_UP
````

```
tunnek="TunnelName"
```

##### MacroDroid

- Connect [macro](Connect_to_Asgard.macro) [png](Connect_to_Asgard.png)
- Disconnect [macro](Disconnect_Asgard.macro) [png](Disconnect_Asgard.png)

##### Termux

Additionally I use a [Termux](https://termux.com/) script (`.termux/tasker/sleep-asgard`).

```
!#/bin/sh

ssh asgard "(sleep 1; sudo pm-suspend) & disown" &
termux-toast -s "Asgard is now asleep"
```

