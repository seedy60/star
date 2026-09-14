# fish

This provider makes your [Fish Audio](https://fish.audio) voice models available to STAR.

Fish Audio is a cloud voice cloning service: you create voice models from reference audio on their website, and every model you own is identified by a model ID. This provider lists all of the voice models attached to your Fish Audio account as STAR voices, plus any public Voice Library voices you pin by ID, and synthesizes with them via Fish Audio's `/v1/tts` endpoint.

## Setup

1. Create or save some voice models on [fish.audio](https://fish.audio).
2. Generate an API key from your Fish Audio account page.
3. Run `python fish.py --configure` (from the provider/fish directory) and paste your API key, or edit fish.ini by hand and add `api_key = <your key>`.
4. Run the provider and your voice models will show up as STAR voices.

## Configuration options

* **api_key**: Your Fish Audio bearer token, required for listing voices and synthesizing speech.
* **tts_model**: The Fish Audio backend model to request, sent in the `model` HTTP header. Defaults to `s2.1-pro-free` (the free developer tier). Other valid values include `s1`, `s2-pro`, `s2.1-pro` and `drama-3-preview`.
* **latency**: The latency/quality trade-off for synthesis, one of `normal` (best quality), `balanced` or `low` (lowest latency). Defaults to `normal`.
* **pinned_voices**: Fish Audio voice model IDs from the public Voice Library to always expose as STAR voices, even if you own no models of your own. One ID per line, optionally as `ID|Label` to control the displayed voice name, for example `6a1f9c2e...|Epic Narrator`. Pins without a label show the model's title as reported by Fish Audio, falling back to the raw model ID if the model cannot be looked up (deleted, made private, or a network error). Blank lines and lines starting with `#` are ignored. Any public model ID works as a `reference_id` in the Fish Audio API without being saved to your account, so these voices synthesize immediately; if you use them on a coagulator, other users can select them like any other STAR voice. The config dialog includes a multiline box for editing this option.

## Notes

* The first time the provider starts it pages through all of your voice models (`GET /model?self=true`), so a large library means a slightly slower startup.
* Speech output is returned as MP3; STAR handles other audio formats fine.
* The STAR rate parameter is mapped to Fish Audio's prosody speed (a value of 1 means normal speed), rate 10 speaking roughly half again as fast as normal. Pitch is not currently supported.
* Voice names in STAR are the Fish Audio model titles as they appear on the website; the provider remembers the underlying model IDs itself. Pinned library voices appear under their custom label, or their raw model ID when no label is given.
* If a voice on a coagulator answers with a Fish Audio TTS error, check that its model ID still exists and is public; a pinned voice whose model is deleted or made private by its owner will stop synthesizing.
