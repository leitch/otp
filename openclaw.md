# Openclaw Commands

```sh
openclaw message send --channel telegram --target 8416538418 --message “Hi”
openclaw message send --channel telegram --target 8416538418 --message "Choose:" \
  --buttons '[ [{"text":"Yes","callback_data":"cmd:yes"}], [{"text":"No","callback_data":"cmd:no"}] ]'

killall -9 node 2>/dev/null
```

## Github

```sh
curl -sS https://webi.sh/gh | sh
gh auth login
```

## Opencode

```sh
pnpm add -g opencode-ai
curl -fsSL https://opencode.ai/install | bash

http://127.0.0.1:18789/?token=1c284b12595d502a033c82b31a7c1c697780f57654f85a2d

curl http://192.168.40.60:11777/api/tags
```

## Upgrade Openclaw

```sh
sudo chown -R $(whoami) ~/.npm
sudo chown -R $(whoami) /usr/local/lib/node_modules
npm cache clean --force
openclaw gateway restart
openclaw doctor --repair
openclaw devices list
openclaw devices approve
openclaw configure

tar -cvzf openclaw_backup.tar.gz ~/.openclaw

clawhub search "keyword"
clawhub inspect <skill-slug>
clawhub list

Install shared skills from the home folder:
clawhub install <skill-slug> --global
clawhub uninstall <skill-slug> --global

Install skills from the agent folder:
clawhub install <skill-slug> --project
clawhub uninstall <skill-slug> --project
```

## Enable Sandbox Mode

```sh
openclaw chat --sandbox
export OPENCLAW_SANDBOX=true
openclaw chat --dry-run
Ask agent: “List all tools you currently have access to and their permission levels."
```
