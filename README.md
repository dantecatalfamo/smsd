# smsd

Minimal two-way SMS backend for one or more SignalWire numbers. It does three things:

- Takes inbound SMS/MMS from SignalWire's webhook, checks the signature and stores the message (MMS media is downloaded locally)
- Groups messages into conversations by your number and the other party's
- Lets you send replies, with or without media, through a small bearer-token API

Single binary, stdlib HTTP, SQLite via `modernc.org/sqlite` (no cgo).

## Setup

```sh
go build -o smsd .
```

Environment:

| Var | Example | Notes |
|---|---|---|
| `PUBLIC_URL` | `https://sms.example.com` | Exact public base URL SignalWire calls. Used for signature checks and the status callback. A path prefix is allowed; a query, fragment or credentials are not. |
| `SW_SPACE` | `yourspace.signalwire.com` | Host name only, no `https://` |
| `SW_PROJECT_ID` | | API Credentials page |
| `SW_API_TOKEN` | | API token; needs the Messaging and Numbers scopes |
| `SW_SIGNING_KEY` | `PSK_...` | API Credentials page → Signing Key |
| `APP_TOKEN` | long random string | Protects `/api/*` |
| `ADDR` | `:8080` | optional |
| `DB_PATH` | `smsd.db` | optional |
| `MEDIA_DIR` | `media` | optional; where inbound MMS media is saved |
| `SKIP_SIGNATURE` | `1` | dev only; refused unless `ADDR` is loopback, e.g. `127.0.0.1:8080` |

smsd checks these at startup and reports every missing or malformed one.

In SignalWire, set **Message Handling** to a **SWML Webhook** on each number smsd should handle:
`POST https://sms.example.com/webhook/sms`. smsd answers each inbound message with a SWML document that just `receive`s it.

Webhooks are verified with `X-SignalWire-Signature`, which is hex HMAC-SHA1 of the URL plus the raw JSON body. Don't put basic-auth credentials in the webhook URL: SignalWire includes them in what it signs, and `PUBLIC_URL` won't have them.

Any number whose webhook points at smsd is handled; there is no list of numbers to configure. Replies can go out from any number in the SignalWire project, so keep numbers smsd shouldn't send from in a different project. Inbound messages with a direction other than `inbound` are acknowledged and dropped.

## API

All `/api` calls need `Authorization: Bearer $APP_TOKEN`. A conversation is between one of your numbers and a peer, and both are in the path. Each can be an E.164 number (`+16135551234` or `%2B16135551234`), a short code, or an alphanumeric sender ID.

```sh
# list the project's phone numbers, as SignalWire describes them
curl -H "Authorization: Bearer $APP_TOKEN" $PUBLIC_URL/api/numbers

# list conversations on all your numbers (newest first)
curl -H "Authorization: Bearer $APP_TOKEN" $PUBLIC_URL/api/conversations

# list conversations on one of your numbers
curl -H "Authorization: Bearer $APP_TOKEN" $PUBLIC_URL/api/numbers/%2B16135550000/conversations

# messages in one conversation (oldest first; page with ?before=<id>&limit=50)
curl -H "Authorization: Bearer $APP_TOKEN" $PUBLIC_URL/api/numbers/%2B16135550000/conversations/%2B16135551234

# reply (sent from the number in the path)
curl -H "Authorization: Bearer $APP_TOKEN" -d '{"body":"hey!"}' \
  $PUBLIC_URL/api/numbers/%2B16135550000/conversations/%2B16135551234/messages

# reply with media: upload files (repeat -F media=@... up to 7 times)
curl -H "Authorization: Bearer $APP_TOKEN" -F body='look' -F media=@cat.jpg \
  $PUBLIC_URL/api/numbers/%2B16135550000/conversations/%2B16135551234/messages

# forward an attachment smsd already has (a media item's "file")
curl -H "Authorization: Bearer $APP_TOKEN" -d '{"body":"fwd","media_files":["42-0.jpg"]}' \
  $PUBLIC_URL/api/numbers/%2B16135550000/conversations/%2B16135551234/messages

# fetch a saved MMS attachment (the name is a media item's "file")
curl -H "Authorization: Bearer $APP_TOKEN" -O $PUBLIC_URL/api/media/42-0.jpg
```

Messages carry every field SignalWire sends: `signalwire_id`, `project_id`, `space_id`, `direction` (`inbound`/`outbound`), `type` (`sms`/`mms`), `from`, `to`, `body` (null on media-only MMS), `segments`, `timestamp` (SignalWire's time) and `media`. smsd adds `number` (yours: `to` if inbound, `from` if outbound), `peer` (the other party), `status`, `error_code`/`error_message`/`status_at` from the current status, and `created_at` (when smsd stored it). The exact payload SignalWire sent is also kept in the database's `raw` column.

Each `media` item has `url`, `content_type` and `size` as SignalWire reported them. Attachments are downloaded in the background over https (up to 25 MB each, 60s each) so they outlive SignalWire's URLs; `file` and `served_type` fill in once a download finishes. Downloads that fail or are cut off by a restart are retried at the next startup for messages from the last 72 hours.

`/api/media/{file}` serves only files smsd downloaded, with the type recorded at download time (`served_type`). Images, audio and video display inline; anything else (HTML, SVG, text, vCards...) is sent as a download. Every response carries `Content-Security-Policy: sandbox` and `X-Content-Type-Options: nosniff`.

Replies go out through SignalWire's messaging REST API (`POST /api/messaging/messages`). A reply needs a body, media, or both. Media can be uploaded (`multipart/form-data` with `body`, `media` and `media_files` fields) or forwarded by file name (`media_files`, in JSON or multipart), up to 7 per message and 5 MB per request. Only [types SignalWire accepts for MMS](https://signalwire.com/docs/platform/messaging/mime-types) are allowed; a missing upload type is sniffed from the content. SignalWire delivers about 1.2 MB per MMS on local numbers and 750 KB on toll-free, so keep attachments small.

SignalWire fetches outgoing attachments itself, from `GET /media-out/{file}` on `PUBLIC_URL`. That route needs no token, but serves only links smsd signed (HMAC keyed from `APP_TOKEN`, covering the file, its type and an expiry 24 hours out). Rotating `APP_TOKEN` revokes outstanding links. Uploaded files are kept in `MEDIA_DIR` like received ones and appear on the stored message's `media`. A reply is recorded even if the client disconnects mid-request. If SignalWire doesn't answer within 15s the API returns 504: the message may have gone out, so check before retrying.

Delivery status callbacks arrive at `POST /webhook/status` and are all kept, raw, in the `status_events` table. A message's `status`, `error_code`, `error_message` and `status_at` come from its newest event (by SignalWire's timestamp, then how far along the status is), so callbacks that arrive out of order or before the message is stored can't overwrite a newer status.

## Events

Three server-sent event streams push messages as they happen: every message on every number, every message on one of your numbers, or one conversation.

```sh
curl -N -H "Authorization: Bearer $APP_TOKEN" $PUBLIC_URL/api/events
curl -N -H "Authorization: Bearer $APP_TOKEN" $PUBLIC_URL/api/numbers/%2B16135550000/events
curl -N -H "Authorization: Bearer $APP_TOKEN" $PUBLIC_URL/api/numbers/%2B16135550000/conversations/%2B16135551234/events
```

Each event's data is a whole message, as the API returns it:

- `message`: a new message, inbound or outbound. Its SSE `id` is the message's `id`.
- `update`: a stored message changed, after a delivery status callback or an attachment finishing its download. Updates have no `id`.

Reconnect with `Last-Event-ID` (EventSource clients do this themselves) to get the messages stored since that id before live events resume. Missed updates are not replayed, so refetch the conversation if you need current statuses. A stream that falls too far behind is closed, and catches up the same way when the client reconnects. A `: ping` comment every 25 seconds keeps idle connections open through proxies. Streams take the same bearer token as the rest of the API, or a ticket. The browser's `EventSource` can't send headers, so it uses a ticket instead.

### Tickets

`POST` to a stream's path plus `/ticket`, with the bearer token, to get a ticket for that one stream:

```sh
curl -X POST -H "Authorization: Bearer $APP_TOKEN" \
  $PUBLIC_URL/api/numbers/%2B16135550000/conversations/%2B16135551234/events/ticket
# {"ticket":"1793984400.9f2c...","expires_at":"2026-11-06T17:00:00Z"}
```

Then open the stream with `?ticket=`:

```js
const es = new EventSource(`${base}/api/numbers/%2B16135550000/conversations/%2B16135551234/events?ticket=${ticket}`);
```

A ticket opens only the stream it was issued for, and only within 60 seconds. It is checked when the stream opens, so an open stream keeps running after its ticket expires. A ticket is signed with a key derived from `APP_TOKEN`, so rotating the token invalidates outstanding tickets. A ticket can't be used for any other API call.

When a stream drops, `EventSource` reconnects with the same URL, and once the ticket has expired that fails with 401 and `EventSource` gives up (`readyState` becomes `CLOSED`). Then get a new ticket and open a new `EventSource`, passing the last event id it saw as `?last_event_id=` (a new `EventSource` can't set the `Last-Event-ID` header):

```js
es.onerror = () => {
  if (es.readyState === EventSource.CLOSED) reconnect(lastEventId); // new ticket, then ...&last_event_id=${lastEventId}
};
```

## Extending

- **Notifications / chat bridge:** implement `Notifier` (`handlers.go`) and replace `logNotifier` in `main.go`. That's where Telegram, Matrix or ntfy plugs in. It runs in the background, so it can block without delaying SignalWire's webhook. To reply from the bridge, call `sw.Send` and `store.Insert` the same way `handleSend` does.
- **Auto-replies:** in `handleInbound`, return a SWML document with a `reply` step in place of `receive`, e.g. `{"version":"1.0.0","sections":{"main":[{"reply":{"body":"Thanks!"}}]}}`. A reply sent that way isn't stored in the database.
- **Behind a reverse proxy:** `PUBLIC_URL` must match what SignalWire calls exactly (scheme, host, port), or signature checks fail.
