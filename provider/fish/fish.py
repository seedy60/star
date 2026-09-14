# Fish Audio (https://fish.audio) provider for STAR.
# Requires no extra dependencies beyond the STAR core.
import asyncio
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

import wx

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from provider import star_provider

FISH_API_BASE = "https://api.fish.audio"

# Value of the "model" header sent with each /v1/tts request. Configurable because
# Fish Audio occasionally renames or adds models (s1, s2-pro, s2.1-pro,
# s2.1-pro-free, drama-3-preview at the time of writing).
DEFAULT_TTS_MODEL = "s2.1-pro-free"


def unique_voice_key(title, voices):
	"""Returns title, or title 2, title 3 and so on if voices already contains an entry with that name."""
	key = title
	number = 2
	while key in voices: key = f"{title} {number}"; number += 1
	return key


def parse_pinned_voices(value):
	"""Parses the pinned_voices config option. One entry per line, either 'id' or 'id|Label'. Blank lines and lines starting with # are ignored."""
	pins = []
	for line in (value or "").splitlines():
		line = line.strip()
		if not line or line.startswith("#"): continue
		if "|" in line: voice_id, label = [p.strip() for p in line.split("|", 1)]
		else: voice_id, label = line, ""
		if voice_id: pins.append((voice_id, label))
	return pins


class fish(star_provider):
	def __init__(self):
		super().__init__(synthesis_audio_extension="mp3")

	def get_api_key(self):
		return self.config.get("api_key", "")

	async def fish_request(self, method, path, body = None):
		"""Makes a request against the Fish Audio API, returning either the parsed JSON response, the raw bytes for binary endpoints, or a string describing any error."""
		headers = {"Authorization": f"Bearer {self.get_api_key()}"}
		data = None
		if body is not None:
			data = json.dumps(body).encode()
			headers["Content-Type"] = "application/json"
		request = urllib.request.Request(FISH_API_BASE + path, data = data, headers = headers, method = method)
		def do_request():
			with urllib.request.urlopen(request, timeout = 60) as r:
				if r.headers.get_content_type() == "application/json": return json.loads(r.read())
				return r.read()
		try:
			return await asyncio.to_thread(do_request)
		except urllib.error.HTTPError as e:
			try: detail = e.read().decode(errors = "replace")
			except Exception: detail = ""
			return f"Fish Audio API error {e.code}: {detail}"
		except Exception as e:
			return f"Error communicating with the Fish Audio API: {e}"

	async def get_voice_title(self, voice_id):
		"""Fetches the title of any Fish Audio voice model by ID, returning an empty string if it cannot be looked up (deleted, private or a network/API error)."""
		result = await self.fish_request("GET", f"/model/{voice_id}")
		if type(result) == dict: return result.get("title") or ""
		return ""

	async def get_voices(self):
		"""Retrieves all of the user's own voice models as this provider's voices. Returns a dictionary of full_name being the voice model's ID and values containing extra metadata."""
		if not self.get_api_key(): return "No Fish Audio API key configured. Run this provider with --configure to set one."
		try:
			voices = {}
			pins = parse_pinned_voices(self.config.get("pinned_voices", ""))
			page_number = 1
			while True:
				query = urllib.parse.urlencode({"self": "true", "page_size": 100, "page_number": page_number})
				result = await self.fish_request("GET", f"/model?{query}")
				if type(result) == str: return result
				for v in result.get("items", []):
					if not v.get("_id"): continue
					voices[unique_voice_key(v.get("title") or "unknown voice", voices)] = {"full_name": v["_id"]}
				if not result.get("has_more"): break
				page_number += 1
			# Pinned library voices are always exposed as STAR voices. Entries without a custom label have their title fetched from the API, falling back to the raw ID if the model cannot be looked up.
			owned_ids = {v["full_name"] for v in voices.values()}
			pins = [(voice_id, label) for voice_id, label in pins if voice_id not in owned_ids]
			unlabeled = [voice_id for voice_id, label in pins if not label]
			titles = dict(zip(unlabeled, await asyncio.gather(*[self.get_voice_title(v) for v in unlabeled]))) if unlabeled else {}
			for voice_id, label in pins:
				voices[unique_voice_key(label or titles.get(voice_id) or voice_id, voices)] = {"full_name": voice_id}
			if not voices: return "No Fish Audio voice models were found for your API key. Clone a voice on https://fish.audio first, or pin library voice IDs under pinned_voices in fish.ini."
			return voices
		except Exception as e:
			return f"Error listing Fish Audio voices: {e}"

	async def synthesize(self, voice: str, text: str, rate=None, pitch=None):
		if not self.get_api_key(): return "Fish Audio API key is missing. Run this provider with --configure to set it."
		body = {
			"text": text,
			"reference_id": voice,
			"format": "mp3",
			"latency": self.config.get("latency", "normal"),
			"normalize": True,
		}
		if rate is not None:
			# STAR rates run from -10 to 10, Fish Audio's prosody speed is a multiplicative factor where 1 means normal speed.
			try:
				body["prosody"] = {"speed": round(1.0 + 0.05 * float(rate), 2)}
			except ValueError:
				pass
		headers = {"Content-Type": "application/json", "model": self.config.get("tts_model", DEFAULT_TTS_MODEL)}
		request = urllib.request.Request(FISH_API_BASE + "/v1/tts", data = json.dumps(body).encode(), headers = {"Authorization": f"Bearer {self.get_api_key()}", **headers}, method = "POST")
		def do_request():
			with urllib.request.urlopen(request, timeout = 300) as r:
				return r.read()
		try:
			return await asyncio.to_thread(do_request)
		except urllib.error.HTTPError as e:
			try: detail = e.read().decode(errors = "replace")
			except Exception: detail = ""
			return f"Fish Audio TTS error {e.code}: {detail}"
		except Exception as e:
			return f"Error synthesizing speech with Fish Audio: {e}"

	def add_configuration_options(self, panel):
		wx.StaticText(panel, -1, "Fish Audio API &Key")
		panel.api_key = wx.TextCtrl(panel, value = self.config.get("api_key", ""))
		wx.StaticText(panel, -1, "TTS &model (s1, s2-pro, s2.1-pro, s2.1-pro-free, drama-3-preview)")
		panel.tts_model = wx.TextCtrl(panel, value = self.config.get("tts_model", DEFAULT_TTS_MODEL))
		wx.StaticText(panel, -1, "&Latency (low, balanced or normal)")
		panel.latency = wx.TextCtrl(panel, value = self.config.get("latency", "normal"))
		wx.StaticText(panel, -1, "&Pinned library voices, one per line as model ID or ID|Label")
		panel.pinned_voices = wx.TextCtrl(panel, value = self.config.get("pinned_voices", ""), style = wx.TE_MULTILINE)
		panel.pinned_voices.SetToolTip("Fish Audio voice model IDs from the public Voice Library to always expose as STAR voices, even if you own no models. One per line, optionally as ID|Label to control the displayed voice name.")

	def write_configuration_options(self, panel, config):
		config["api_key"] = panel.api_key.Value
		config["tts_model"] = panel.tts_model.Value if panel.tts_model.Value else DEFAULT_TTS_MODEL
		config["latency"] = panel.latency.Value if panel.latency.Value else "normal"
		config["pinned_voices"] = panel.pinned_voices.Value

if __name__ == "__main__":
	fish()
