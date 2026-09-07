# capability-authority

Capability plane: signed short-lived capabilities, executor-only side effects,
gated hands (no ambient shell/kubectl/keys), production fail-closed profile.

```bash
git clone https://github.com/doitupsolutions810-crow/capability-authority.git
cd capability-authority
pip install -r requirements-lab.txt
export PYTHONPATH=$PWD
python3 scripts/demo_hands.py
python3 scripts/demo_production_profile.py
python3 scripts/demo_issue_execute.py
python3 scripts/demo_remaining_rings.py
python3 -m plane_service.server   # :8090
```

Optional TLS front door:

```bash
bash scripts/gen_front_door_tls.sh
FRONT_DOOR_TLS=1 FRONT_DOOR_CERT=config/tls/front_door.crt FRONT_DOOR_KEY=config/tls/front_door.key \
  python3 gateway/https_front_door.py
```

See `docs/` and `OVERLAY.md`.
