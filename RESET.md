# Clean reset (fixes any password / state drift)

If Kibana or Elasticsearch starts rejecting the password, the running state and
your `.env` have drifted (usually from partial re-runs). The cure is a clean,
matched start. This wipes lab DATA (not your scenarios/config) - fine, since the
compromise is re-seeded on install.

## Windows
```powershell
docker compose down -v
Remove-Item .env -ErrorAction SilentlyContinue
powershell -ExecutionPolicy Bypass -File .\install.ps1 -NoWindowsVictim
```

## Linux / macOS
```bash
docker compose down -v
rm -f .env
./install.sh
```

Why delete `.env`? Elasticsearch only sets the `elastic` password on the FIRST
init of its data volume. If `.env` and the volume ever hold different passwords,
you get 401s. Wiping the volume (`down -v`) AND `.env` together forces both to be
regenerated in sync on the next install - they can never mismatch.

## Verify after reset
```
docker compose ps                 # elasticsearch Healthy; es-init/kibana-setup Exited(0)
```
Then open http://localhost:5601 and log in as elastic with the password the
installer printed (also in the new .env).
