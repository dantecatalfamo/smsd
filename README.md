# smsd

Minimal two-way SMS backend for a SignalWire number. It does three things:

- Takes inbound SMS/MMS from SignalWire's webhook, checks the signature and stores the message (MMS media is downloaded locally)
- Groups messages into conversations by the other party's number
- Lets you send replies through a small bearer-token JSON API

Single binary, stdlib HTTP, SQLite via `modernc.org/sqlite` (no cgo).

## Setup

```sh
go build -o smsd .
```

Environment:

| Var | Example | Notes |
|---|---|---|
| `PUBLIC_URL` | `https://sms.example.com` | Exact public base URL SignalWire calls. Used for signature checks and the status callback. |
| `SW_SPACE` | `yourspace.signalwire.com` | |
| `SW_PROJECT_ID` | | API Credentials page |
| `SW_API_TOKEN` | | API token |
| `SW_SIGNING_KEY` | `PSK_...` | API Credentials page → Signing Key |
| `SW_FROM_NUMBER` | `+16135550000` | Your SignalWire number, E.164 |
| `APP_TOKEN` | long random string | Protects `/api/*` |
| `ADDR` | `:8080` | optional |
| `DB_PATH` | `smsd.db` | optional |
| `MEDIA_DIR` | `media` | optional; where inbound MMS media is saved |
| `SKIP_SIGNATURE` | `1` | dev only |

In SignalWire, set the number's **inbound messaging** handler to a cXML/LaML webhook:
`POST https://sms.example.com/webhook/sms`

Inbound messages addressed to any number other than `SW_FROM_NUMBER` are acknowledged and dropped.

## API

All `/api` calls need `Authorization: Bearer $APP_TOKEN`. Write `+` in the path as `%2B`.

```sh
# list conversations (newest first)
curl -H "Authorization: Bearer $APP_TOKEN" $PUBLIC_URL/api/conversations

# messages in one conversation (oldest first; page with ?before=<id>&limit=50)
curl -H "Authorization: Bearer $APP_TOKEN" $PUBLIC_URL/api/conversations/%2B16135551234

# reply
curl -H "Authorization: Bearer $APP_TOKEN" -d '{"body":"hey!"}' \
  $PUBLIC_URL/api/conversations/%2B16135551234/messages

# fetch a saved MMS attachment (names come from a message's media_files)
curl -H "Authorization: Bearer $APP_TOKEN" -O $PUBLIC_URL/api/media/SMxxxx-0.jpg
```

Inbound MMS media is downloaded in the background (up to 25 MB per file) so it outlives SignalWire's URLs. `media` keeps the original URLs; `media_files` fills in once the downloads finish.

Delivery status updates arrive at `POST /webhook/status` and are written to the message's `status` field. A callback that arrives before its message is stored is held and applied when the message is stored.

## Extending

- **Notifications / chat bridge:** implement `Notifier` (`handlers.go`) and replace `logNotifier` in `main.go`. That's where Telegram, Matrix or ntfy plugs in. To reply from the bridge, call `sw.Send` and `store.Insert` the same way `handleSend` does.
- **Auto-replies:** in `handleInbound`, return `<Response><Message>…</Message></Response>` in place of the empty response.
- **Behind a reverse proxy:** `PUBLIC_URL` must match what SignalWire calls exactly (scheme, host, port), or signature checks fail.
