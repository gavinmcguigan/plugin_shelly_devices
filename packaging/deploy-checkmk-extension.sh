#!/usr/bin/env bash
# Copies checkmk_extension/cmk_addons/plugins/shelly into an OMD site's
# local plugin tree and restarts the site so it picks up the change.
# Needs sudo (writes under /omd/sites/<site>, owned by the site user) --
# run it yourself, don't wrap it in another sudo/script.
#
# Restarting just Apache is NOT enough for check-plugin (agent_based/)
# changes -- the check engine's plugin registry isn't reloaded by that,
# only by a full site restart.
#
# The site user generally can't read into $HOME (traversal permission),
# so this stages a copy under /tmp first rather than reading the repo
# path directly as the site user.
set -euo pipefail

SITE="${1:?Usage: deploy-checkmk-extension.sh <site>}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${REPO_ROOT}/checkmk_extension/cmk_addons/plugins/shelly"
STAGING="/tmp/shelly"
DEST="/omd/sites/${SITE}/local/lib/python3/cmk_addons/plugins/shelly"

rm -rf "$STAGING"
cp -r "$SRC" "$STAGING"

sudo rm -rf "$DEST"
sudo cp -r "$STAGING" "$DEST"
sudo chown -R "${SITE}:${SITE}" "$DEST"
sudo omd restart "$SITE"

echo "Deployed to ${DEST}."
