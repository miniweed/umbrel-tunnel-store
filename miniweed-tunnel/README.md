# Tunnel

Tunnel expone servicios internos de Umbrel mediante un VPS propio usando WireGuard + Caddy.

## Flujo básico

1. Genera claves WireGuard desde la UI.
2. Configura IP del VPS.
3. Descarga y ejecuta el script de setup en el VPS.
4. Pega la clave pública del VPS en la UI y guarda.

## Auth por clave pública (CLI)

El backend acepta claves `ssh-ed25519` (OpenSSH) o DER/SPKI base64.

### 1) Registrar clave pública

```bash
API_URL="http://umbrel.local:3016"
API_TOKEN="<token_api>"
KEY_NAME="laptop-cli"
PUBKEY="$(cat ~/.ssh/id_ed25519.pub)"

curl -sS -X POST "$API_URL/api/auth/pubkeys" \
  -H "Content-Type: application/json" \
  -H "x-tunnel-api-token: $API_TOKEN" \
  -d "{\"name\":\"$KEY_NAME\",\"publicKey\":\"$PUBKEY\"}"
```

Guarda el `keyId` de la respuesta.

### 2) Pedir challenge

```bash
KEY_ID="<keyId>"

CHALLENGE_JSON="$(curl -sS -X POST "$API_URL/api/auth/challenge" \
  -H "Content-Type: application/json" \
  -d "{\"keyId\":\"$KEY_ID\"}")"

CHALLENGE_ID="$(printf '%s' "$CHALLENGE_JSON" | python3 - <<'PY'
import json,sys
data=json.loads(sys.stdin.read())
print(data['challengeId'])
PY
)"

NONCE_B64="$(printf '%s' "$CHALLENGE_JSON" | python3 - <<'PY'
import json,sys
data=json.loads(sys.stdin.read())
print(data['nonce'])
PY
)"
```

### 3) Firmar challenge y verificar

```bash
SIG_B64="$(NONCE_B64="$NONCE_B64" node -e '
const fs=require("fs");
const crypto=require("crypto");
const nonce=Buffer.from(process.env.NONCE_B64,"base64");
const key=fs.readFileSync(process.env.PRIV_KEY_PATH||`${process.env.HOME}/.ssh/id_ed25519`,"utf8");
const sig=crypto.sign(null, nonce, key);
process.stdout.write(sig.toString("base64"));
')"

VERIFY_JSON="$(curl -sS -X POST "$API_URL/api/auth/verify" \
  -H "Content-Type: application/json" \
  -d "{\"challengeId\":\"$CHALLENGE_ID\",\"signature\":\"$SIG_B64\"}")"

SESSION_TOKEN="$(printf '%s' "$VERIFY_JSON" | python3 - <<'PY'
import json,sys
print(json.loads(sys.stdin.read())['sessionToken'])
PY
)"

curl -sS "$API_URL/api/config" -H "Cookie: mw_session=$SESSION_TOKEN"
```

Nota: el backend espera firma Ed25519 "raw" en base64 sobre los bytes del `nonce` (después de decodificar base64).

## Rotación de claves (manual asistida)

1. Preparar plan de rotación y script de rollback VPS:

```bash
curl -sS -X POST "$API_URL/api/rotate/prepare" \
  -H "Content-Type: application/json" \
  -H "x-tunnel-api-token: $API_TOKEN"
```

2. Ejecutar en el VPS el script retornado por el endpoint.
3. Confirmar desde API:

```bash
curl -sS -X POST "$API_URL/api/rotate/confirm" \
  -H "Content-Type: application/json" \
  -H "x-tunnel-api-token: $API_TOKEN" \
  -d '{"planId":"<planId>","apply":true}'
```

## Kill switch remoto (script)

Descarga de script de emergencia:

```bash
curl -sS "$API_URL/api/kill-switch/script?format=plain" \
  -H "x-tunnel-api-token: $API_TOKEN" \
  -o miniweed-killswitch.sh
chmod +x miniweed-killswitch.sh
```

El script detiene `wg-quick@wg0` y bloquea UDP/51820.

Opcionalmente puedes parametrizar el puerto o archivo de estado:

```bash
WG_PORT=51820 STATUS_FILE=/tmp/miniweed.status sudo bash miniweed-killswitch.sh
```

Instalación opcional como servicio systemd en el VPS (ejecución local, sin API del VPS):

```bash
sudo install -m 700 miniweed-killswitch.sh /mnt/killswitch.sh
sudo bash miniweed-tunnel/vps-setup/killswitch-service.sh
sudo systemctl start miniweed-killswitch.service
```
