# Supabase API Key Persistence Setup

## 1) Create table
Run:

- `external/key-spring/backend/supabase/api_keys.sql`

in your Supabase SQL editor.

## 2) Set backend env vars

```env
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_SERVICE_ROLE_KEY=<service-role-key>
KAIRO_API_KEYS_TABLE=api_keys
```

Optional existing auth var:

```env
KAIRO_ADMIN_KEY=<hex key>
```

## 3) Restart backend
On boot, backend will:
- load key records from Supabase
- merge/admin-mark env admin key if provided
- keep syncing key changes + wallet bindings back to Supabase

## Notes
- Raw API keys are never stored; only `sha256(key)` (`key_hash`) is persisted.
- Full API key is only returned once at key creation time.
- Wallet ownership mapping persists in `wallet_ids` so `/api/policy/receipt/mint`, `/api/presign/request`, `/api/sign/request` survive restarts.
