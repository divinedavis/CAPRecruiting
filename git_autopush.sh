#!/bin/bash
cd /home/recruiting/bearcats

# Stage only tracked files that changed (respects .gitignore)
git add -u

# Also pick up any new untracked files (still respects .gitignore)
git add .

# Only commit if there are staged changes
if ! git diff --cached --quiet; then
    git commit -m "Auto-commit: 2026-02-28 14:19"
    git push origin main
fi
