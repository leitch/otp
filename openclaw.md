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

Device pairing:
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

## Copy from wsl to macmini

scp -r <wsl folder> <user>@<ip>:~/Downloads

# Display openc
law status in json
openclaw status --json 2>/dev/null

# Check the gateway error log for startup version info
head -50 ~/.openclaw/logs/gateway.err.log

# Check the gateway log for version at startup
head -50 ~/.openclaw/logs/gateway.log

# Check how the launchd service was registered
launchctl print gui/$(id -u)/ai.openclaw.gateway

# Open the plist and update the version
vi ~/Library/LaunchAgents/ai.openclaw.gateway.plist

# Find OPENCLAW_SERVICE_VERSION and update 
sed -i '' 's/2026.2.21-2/2026.3.1/g' ~/Library/LaunchAgents/ai.openclaw.gateway.plist

# Reload the daemon
launchctl unload ~/Library/LaunchAgents/ai.openclaw.gateway.plist
launchctl load ~/Library/LaunchAgents/ai.openclaw.gateway.plist

# Confirm version
launchctl print gui/$(id -u)/ai.openclaw.gateway | grep SERVICE_VERSION
openclaw status --json | grep version
openclaw --version

# Browser setup
openclaw config set browser.enabled true --json
openclaw config set browser.defaultProfile "openclaw"
openclaw config set browser.headless true --json
npx playwright install chromium

find ~/Library/Caches/ms-playwright -name "Google Chrome for Testing"
openclaw config set browser.executablePath "/Users/oo/Library/Caches/ms-playwright/chromium-1208/chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"

xattr -rd com.apple.quarantine "/Users/oo/Library/Caches/ms-playwright/chromium-1208/chrome-mac-x64/Google Chrome for Testing.app"

openclaw browser --browser-profile openclaw start
openclaw browser --browser-profile openclaw open https://google.com
openclaw browser --browser-profile openclaw snapshot
