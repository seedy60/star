# TikTok text to speech provider for STAR.
# By default uses Weilbyte's community wrapper endpoint, which needs no configuration at all;
# a direct connection to TikTok's internal mobile app endpoint via a sessionid cookie is available as a fallback backend.
# Requires no extra dependencies beyond the STAR core.
import asyncio
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

import wx

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from provider import star_provider

# Weilbyte backend: a community Cloudflare worker that maintains its own pool of TikTok sessions, so no cookie is needed.
WEILBYTE_URL = "https://tiktok-tts.weilnet.workers.dev/api/generation"
# TikTok's internal mobile app endpoint, used by the direct backend.
TIKTOK_TTS_URL = "https://api16-normal-v6.tiktokv.com/media/api/text/speech/invoke/"
# User agent copied from TikTok's Android app, as expected by the internal TTS endpoint (and accepted by the Weilbyte worker).
TIKTOK_USER_AGENT = "com.zhiliaoapp.musically/2022600030 (Linux; U; Android 7.1.2; es_ES; SM-G988N; Build/NRD90M;tt-ok/3.12.13.1)"
# The Weilbyte worker rejects non-browser requests, so a browser user agent is sent with every backend request.
BROWSER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"

# The Weilbyte worker limits text to 300 UTF-8 bytes per request and TikTok's endpoint to roughly 300 characters, so longer text is split on sentence boundaries and the audio is concatenated.
MAX_CHUNK_BYTES = 290

# Voice code -> human readable STAR voice name. The list is static: TikTok's API offers no voice listing endpoint.
VOICES = {
	# Disney voices
	"en_us_ghostface": "Ghost Face",
	"en_us_chewbacca": "Chewbacca",
	"en_us_c3po": "C3PO",
	"en_us_stitch": "Stitch",
	"en_us_stormtrooper": "Stormtrooper",
	"en_us_rocket": "Rocket",
	# English voices
	"en_au_001": "English AU Female",
	"en_au_002": "English AU Male",
	"en_uk_001": "English UK Male 1",
	"en_uk_003": "English UK Male 2",
	"en_us_001": "English US Female 1",
	"en_us_002": "Jessie English US Female 2",
	"en_us_006": "English US Male 1",
	"en_us_007": "English US Male 2",
	"en_us_009": "English US Male 3",
	"en_us_010": "English US Male 4",
	# European voices
	"fr_001": "French Male 1",
	"fr_002": "French Male 2",
	"de_001": "German Female",
	"de_002": "German Male",
	"es_002": "Spanish Male",
	# American voices
	"es_mx_002": "Spanish MX Male",
	"br_001": "Portuguese BR Female 1",
	"br_003": "Portuguese BR Female 2",
	"br_004": "Portuguese BR Female 3",
	"br_005": "Portuguese BR Male",
	# Asian voices
	"id_001": "Indonesian Female",
	"jp_001": "Japanese Female 1",
	"jp_003": "Japanese Female 2",
	"jp_005": "Japanese Female 3",
	"jp_006": "Japanese Male",
	"kr_002": "Korean Male 1",
	"kr_003": "Korean Female",
	"kr_004": "Korean Male 2",
	# Singing voices
	"en_female_f08_salut_damour": "Alto Singing",
	"en_male_m03_lobby": "Tenor Singing",
	"en_female_f08_warmy_breeze": "Warmy Breeze Singing",
	"en_male_m03_sunshine_soon": "Sunshine Soon Singing",
	# Other voices
	"en_male_narration": "Narrator",
	"en_male_funny": "Wacky",
	"en_female_emotional": "Peaceful",
}


def sanitize_text(text):
	"""The TikTok endpoint expects text in a query string, so escape or transliterate characters it cannot handle."""
	replacements = {"+": "plus", "&": "and", "%": "percent", "#": "hash", "?": ""}
	for old, new in replacements.items(): text = text.replace(old, new)
	for old, new in (("ä", "ae"), ("ö", "oe"), ("ü", "ue"), ("ß", "ss"), ("Ä", "Ae"), ("Ö", "Oe"), ("Ü", "Ue")):
		text = text.replace(old, new)
	# Spaces are sent as plus signs, matching what the TikTok app itself does.
	return urllib.parse.quote(text, safe = "").replace("%20", "+")


def split_text(text):
	"""Splits text into chunks whose UTF-8 encoded size is at most MAX_CHUNK_BYTES, preferring sentence, clause and finally word boundaries."""
	if len(text.encode("utf-8")) <= MAX_CHUNK_BYTES: return [text]
	chunks = []
	while text:
		if len(text.encode("utf-8")) <= MAX_CHUNK_BYTES: chunks.append(text); break
		# Binary search for the largest prefix that fits the byte budget.
		lo, hi = 1, len(text)
		while lo < hi:
			mid = (lo + hi + 1) // 2
			if len(text[:mid].encode("utf-8")) <= MAX_CHUNK_BYTES: lo = mid
			else: hi = mid - 1
		window = text[:lo]
		# Prefer cutting on sentence, clause and word boundaries, in that order, falling back to a hard cut.
		cut = window.rfind(". ")
		if cut == -1: cut = window.rfind(", ")
		if cut == -1: cut = window.rfind(" ")
		if cut == -1: cut = len(window)
		chunks.append(text[:cut].strip())
		text = text[cut:].strip()
	return [c for c in chunks if c]


class tiktok(star_provider):
	def __init__(self):
		super().__init__(synthesis_audio_extension="mp3")

	def get_backend(self):
		return self.config.get("backend", "weilbyte")

	def get_session_id(self):
		return self.config.get("session_id", "")

	async def synthesize(self, voice: str, text: str, rate=None, pitch=None):
		try:
			if self.get_backend() == "direct" and not self.get_session_id(): return "TikTok session ID is missing. Run this provider with --configure to set one, or switch the backend back to weilbyte."
			audio = b""
			for chunk in split_text(text):
				result = await asyncio.to_thread(self.request_audio, voice, chunk)
				if isinstance(result, str): return result
				audio += result
			return audio
		except Exception as e:
			return f"Error synthesizing speech with TikTok: {e}"

	def request_audio(self, voice, text):
		"""Synchronous worker that synthesizes one chunk on the configured backend and returns the MP3 bytes or an error string."""
		if self.get_backend() == "direct": return self.request_audio_direct(voice, text)
		return self.request_audio_weilbyte(voice, text)

	def request_audio_weilbyte(self, voice, text):
		# The worker responds to POSTs with a 307 redirect to a dispatch host, so redirects are followed by hand since urllib refuses to re-POST automatically.
		url, body = WEILBYTE_URL, json.dumps({"text": text, "voice": voice}).encode()
		for hop in range(5):
			request = urllib.request.Request(url, data = body, headers = {"Content-Type": "application/json", "User-Agent": BROWSER_USER_AGENT}, method = "POST")
			try:
				with urllib.request.urlopen(request, timeout = 60) as r:
					response = json.loads(r.read())
				break
			except urllib.error.HTTPError as e:
				if e.code in (301, 302, 307, 308) and e.headers.get("Location"): url = e.headers["Location"]; continue
				try: detail = e.read().decode(errors = "replace")
				except Exception: detail = ""
				return f"TikTok TTS error {e.code}: {detail}"
			except Exception as e:
				return f"Error communicating with the TikTok TTS endpoint: {e}"
		else:
			return "TikTok TTS error: too many redirects from the Weilbyte endpoint"
		if not response.get("success") or not response.get("data"): return f"TikTok TTS error: {response.get('error', 'unknown error')}"
		return base64.b64decode(response["data"])

	def request_audio_direct(self, voice, text):
		# sanitize_text already percent-encodes the text, so the query string is assembled by hand instead of via urlencode to avoid double encoding.
		query = f"text_speaker={urllib.parse.quote(voice, safe='')}&req_text={sanitize_text(text)}&speaker_map_type=0&aid=1233"
		request = urllib.request.Request(
			TIKTOK_TTS_URL + "?" + query,
			data = b"",
			method = "POST",
			headers = {"User-Agent": TIKTOK_USER_AGENT, "Cookie": f"sessionid={self.get_session_id()}"},
		)
		try:
			with urllib.request.urlopen(request, timeout = 60) as r:
				response = json.loads(r.read())
		except urllib.error.HTTPError as e:
			try: detail = e.read().decode(errors = "replace")
			except Exception: detail = ""
			return f"TikTok TTS error {e.code}: {detail}"
		except Exception as e:
			return f"Error communicating with the TikTok TTS endpoint: {e}"
		if response.get("status_code") != 0 or "data" not in response or not response["data"].get("v_str"):
			return f"TikTok TTS error: {response.get('message', 'unknown error')}"
		return base64.b64decode(response["data"]["v_str"])

	def get_voices(self):
		"""Returns the static voice list, with the human readable names as STAR voice names and the TikTok voice codes in full_name."""
		return {name: {"full_name": code} for code, name in VOICES.items()}

	def add_configuration_options(self, panel):
		wx.StaticText(panel, -1, "Backend")
		panel.backend = wx.Choice(panel, choices = ["weilbyte", "direct"])
		panel.backend.SetStringSelection(self.get_backend())
		panel.backend.SetToolTip("weilbyte uses Weilbyte's community endpoint and needs no configuration. direct talks to TikTok's internal endpoint itself and needs a session ID cookie.")
		panel.session_id_label = wx.StaticText(panel, -1, "TikTok session ID")
		panel.session_id = wx.TextCtrl(panel, value = self.get_session_id())
		panel.session_id.SetToolTip("Only needed for the direct backend: the sessionid cookie from a logged in TikTok browser session. See the provider readme for how to obtain it.")
		def update_session_id_visibility():
			direct = panel.backend.Selection == 1
			panel.session_id_label.Show(direct)
			panel.session_id.Show(direct)
			panel.Layout()
			panel.Fit()
		def on_backend_change(evt):
			update_session_id_visibility()
			if evt: evt.Skip()
		panel.backend.Bind(wx.EVT_CHOICE, on_backend_change)
		update_session_id_visibility()

	def write_configuration_options(self, panel, config):
		config["backend"] = "direct" if panel.backend.Selection == 1 else "weilbyte"
		config["session_id"] = panel.session_id.Value

if __name__ == "__main__":
	tiktok()
