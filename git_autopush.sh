#!/bin/bash
cd /home/recruiting/bearcats

# Stage only tracked files that changed (respects .gitignore)
git add -u

# Also pick up any new untracked files (still respects .gitignore)
git add .

# Only commit if there are staged changes
if ! git diff --cached --quiet; then
    git commit -m "Auto-commit: $(date '+%Y-%m-%d %H:%M')"
fi

# Pull remote changes (rebase), then push
git pull --rebase origin main && git push origin main
