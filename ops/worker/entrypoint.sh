#!/bin/sh
# Decrypt secrets (memory only) and exec the role script.
set -e
export SOPS_AGE_KEY_FILE=/etc/hikoutei-ops/age.key
export ZEN_KEY="$(sops -d /sops/zen_key.txt)"
export PAT="$(sops -d /sops/pr_token.txt)"
if [ "$ROLE" = "worker" ]; then
  if [ ! -d /work/lib/.git ]; then
    git clone -q https://github.com/ManddarinShop/Hikoutei.git /work/lib
  else
    git -C /work/lib fetch -q origin main
  fi
  git -C /work/lib config user.name "ManddarinShop"
  git -C /work/lib config user.email "bot@manddarin.shop"
fi
exec python3 /app/"$ROLE".py
