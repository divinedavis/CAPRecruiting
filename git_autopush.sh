#!/bin/bash
cd /home/recruiting/bearcats

# Only stage tracked files that changed (respects .gitignore, never adds new untracked files)
git add -u

# Only commit if there are staged changes
if ! git diff --cached --quiet; then
    git commit -m "Auto-commit: $(date '+%Y-%m-%d %H:%M')"
fi

# Pull remote changes (rebase), then push
git pull --rebase origin main && git push origin main
