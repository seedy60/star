# tiktok

This provider exposes TikTok's text to speech voices (including the famous "Jessie" voice and the Disney characters) to STAR.

## Backends

The provider supports two backends, selectable in the configuration dialog (`python tiktok.py --configure`) or via the `backend` option in tiktok.ini:

* **weilbyte** (default): Synthesis is sent to Weilbyte's community endpoint (the backend of the tiktok-tts.weilbyte.dev web UI), which maintains its own pool of TikTok sessions. **This backend requires no configuration at all.** Note that it is a free community service, so heavy use is discouraged and availability depends on its maintainer; if the service is down, switch to the direct backend.
* **direct**: The provider talks to the same internal endpoint the TikTok mobile app uses, authenticating with a `sessionid` cookie from a real TikTok account.

## Direct backend setup

1. Log into tiktok.com in your browser.
2. Open the browser's developer tools (F12), go to the storage/application section and find the cookies for tiktok.com.
3. Copy the value of the cookie named `sessionid`.
4. Run `python tiktok.py --configure` (from the provider/tiktok directory), set the backend to `direct` and paste the session ID, or edit tiktok.ini by hand and add `backend = direct` and `session_id = <your value>`.
5. Run the provider and the TikTok voices will show up as STAR voices.

## Legal / ToS warning

The direct backend is not an official or public API. It is an undocumented internal endpoint intended for the TikTok app itself, and it requires a session cookie from a real TikTok account. Using it may violate TikTok's terms of service, and the endpoint may break or start rejecting requests at any time. The Weilbyte backend is subject to the same caveats indirectly, as it calls the same endpoint under the hood. Use at your own risk; the rest of the STAR project takes no responsibility for account or ToS consequences.

## Configuration options

* **backend**: Either `weilbyte` (default, no configuration needed) or `direct` (requires session_id).
* **session_id**: Your TikTok session cookie value, only needed for the direct backend; the field only appears in the configuration dialog once the backend is set to direct. There is no API key; TikTok authenticates via this cookie.

## Notes

* The voice list is static (TikTok's API has no voice listing endpoint), covering the Disney characters, English, European, Asian and singing voices known to work with the endpoint. Both backends share the same voice codes.
* Text longer than roughly 300 UTF-8 bytes is split on sentence/clause boundaries and the returned MP3 chunks are concatenated, since both backends only accept short texts per request.
* For the direct backend, characters the query-string based endpoint cannot handle (`+`, `&`, `%`, `#`, `?`) are replaced, and German umlauts are transliterated, before the request is sent.
* Speech output is returned as MP3; STAR handles other audio formats fine.
* If the direct backend starts failing with messages like "Couldn't load speech. Try again.", your session ID has probably expired: grab a fresh one from your browser and update the configuration. If the weilbyte backend fails with an error from the worker, its session pool is likely temporarily exhausted or the service is down: retry later or switch to the direct backend.
* The STAR rate and pitch parameters are not supported by these endpoints and are ignored.
