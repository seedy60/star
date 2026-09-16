# The original source code for this program is in ../old/coagulator.py. I wrote it using what turned out to be a noncompliant and incomplete web_socket_server framework, so I asked ChatGPT to rewrite it using the python websockets framework and then modified the result to make it work. In the end, Chat GPT is responsible for the asyncio stuff mostly, though even some of that has changed since.
# Provider revision 5 adds provider identification (name plus stable provider_id), per-connection logging, reconnect flood blocking and admin endpoints (/providers, /kick, /unblock) so a coagulator operator can identify and remove malfunctioning or malicious provider connections.
# User revision 5 expects voice lists in the form of dictionaries carrying their provider name, used by the client to present voices in per-provider tabs.
# Web authentication: websocket clients and providers keep HTTP basic auth, while the web frontend uses a session login with argon2id-hashed passwords, CSRF-protected admin actions and per-address login rate limiting.

import asyncio
import argparse
import configobj
import getpass
import hmac
import http.cookies
import json
import logging
import mimetypes
import os
import random
import re
import secrets
import sys
import time
import traceback
import urllib.parse
import websockets
import websockets.asyncio.server

# Passwords are stored as argon2id hashes; the import is guarded so the coagulator still starts (with a warning) if the package is missing.
try:
	from argon2 import PasswordHasher
	from argon2.exceptions import InvalidHashError, VerifyMismatchError
except ImportError:
	PasswordHasher = None

# The default log record format includes the logger name, which is useless noise for a single-file application. The coagulator's own logger is raised to INFO so its sign-in and audit messages always reach the terminal (and flush), while chatty library INFO records stay silent.
logging.basicConfig(format = "%(asctime)s %(levelname)s: %(message)s")
logging.getLogger("coagulator").setLevel(logging.INFO)

def g(): pass #globals
g.provider_rev = 5
g.user_rev = 5
# How many full provider reconnects (to any host) within reconnect_flood_seconds (from coagulator.ini) trigger a temporary block, and how many seconds that block lasts.
g.reconnect_flood_default = 8
g.reconnect_flood_window_default = 60
g.reconnect_block_default = 300
g.next_client_id = 1
g.next_web_id = 10000000
g.sessions = {}
g.login_attempts = {}
g.login_page_csrf = {}

def log(message, level = logging.INFO):
	"""Central logging helper. Messages are both printed to the terminal and stored in the in-memory connection log inspected via the /providers HTTP endpoint."""
	logging.getLogger("coagulator").log(level, message)
	print(message)
	g.connection_log.append({"time": time.time(), "message": message})
	if len(g.connection_log) > g.connection_log_limit: del g.connection_log[:len(g.connection_log) - g.connection_log_limit]

def describe_client(client):
	"""Formats a client dictionary into a human readable name such as provider balcony 3 from 192.168.1.5 for use in log messages."""
	if "provider_name" in client and client.get("remote_address"):
		return f"provider {client['provider_name']} #{client['id']} from {client['remote_address'][0]}"
	if "provider_name" in client: return f"provider {client['provider_name']} #{client['id']}"
	if client.get("remote_address"): return f"client #{client['id']} from {client['remote_address'][0]}"
	return f"client #{client['id']}"

def provider_identity(msg):
	"""Extracts the provider identity from a voices packet. A stable provider_id (a random string persisted by the provider in its config file) lets the operator tell apart and manage multiple connections even when they share a provider name or reconnect with new ports. The provider_name is sanitized as defense in depth: unpatched providers may report a filesystem path (the old default derived from sys.argv[0]), which would leak operator usernames and directory structures into voice tabs and the admin UI."""
	return str(msg.get("provider_id") or ""), sanitize_provider_name(str(msg.get("provider_name") or ""))

def sanitize_provider_name(name):
	"""Turns a reported provider name into a safe display name. Filesystem paths are reduced to their final component, script extensions are stripped, control characters and excessive length are removed."""
	raw = "".join(ch for ch in name if ch.isprintable()).strip()
	parts = [p for p in re.split("[/\\\\]", raw) if p]  # treat both / and backslash as separators regardless of host OS
	clean = parts[-1] if parts else raw
	clean = re.sub("\\.(py|pyc|pyw|exe|bat|cmd)$", "", clean, flags = re.IGNORECASE)
	clean = re.sub("\\s+", " ", clean).strip()
	if len(clean) > 60: clean = clean[:60].rstrip()
	return clean if clean else "unknown"

def is_blocked(address):
	"""Returns the remaining seconds of a temporary block for the given remote address, or 0 if the address is not blocked."""
	until = g.blocklist.get(address[0], 0)
	return max(0, round(until - time.time())) if until > time.time() else 0

def admin_endpoints_enabled():
	"""Admin endpoints default to on and can be turned off with admin_endpoints = False in coagulator.ini or through --configure."""
	return g.config.as_bool("admin_endpoints") if "admin_endpoints" in g.config else True

def admin_users():
	"""The list of usernames allowed to sign into the admin section, from the comma-separated admin_users option in coagulator.ini. ConfigObj may hand the value to us already split into a list, which is handled here too. Defaults to the first configured user for setups created before this list existed."""
	value = g.config.get("admin_users", "")
	entries = value if isinstance(value, list) else str(value).split(",")
	names = [u.strip() for u in entries if str(u).strip()]
	if names: return names
	users = list(g.config.get("users", {}) or {})
	return users[:1]

def parse_cookies(connection):
	"""Parses the Cookie header of an HTTP request into a dictionary."""
	cookie = connection.request.headers.get("Cookie") if getattr(connection, "request", None) else None
	if not cookie: return {}
	try:
		jar = http.cookies.SimpleCookie(cookie)
	except http.cookies.CookieError:
		return {}
	return {k: morsel.value for k, morsel in jar.items()}

def session_username(connection):
	"""Returns the username of the logged-in web session for an HTTP request, or None. Session cookies hold only a random 256-bit token; the token never encodes the username."""
	token = parse_cookies(connection).get("star_session")
	if not token: return None
	session = g.sessions.get(token)
	if not session: return None
	if session["expires"] < time.time():
		del g.sessions[token]
		return None
	return session["username"]

def session_cookie_present(connection):
	"""True when the request carries a session cookie at all (whether or not it is still valid), used to tell an expired session apart from an anonymous visitor."""
	return "star_session" in parse_cookies(connection)

def check_login_rate(address):
	"""Returns the number of seconds an address must still wait before its next login attempt, or 0 when it may proceed. After login_rate_threshold consecutive failures within login_rate_seconds from one address, attempts are refused until the window elapses, which blunts online password guessing."""
	now = time.time()
	attempts = [t for t in g.login_attempts.get(address[0], []) if now - t < g.login_rate_window]
	g.login_attempts[address[0]] = attempts
	if len(attempts) >= g.login_rate_threshold:
		return round(g.login_rate_window - (now - attempts[0])) + 1
	return 0

def record_login_failure(address):
	g.login_attempts.setdefault(address[0], []).append(time.time())

def clear_login_failures(address):
	g.login_attempts.pop(address[0], None)

def stored_password(user_record):
	"""Returns a user's stored password entry as a plain string. ConfigObj turns values containing commas (such as argon2 parameter lists) into lists when loading, so those are reassembled verbatim."""
	value = user_record.get("password", "") if isinstance(user_record, dict) else ""
	if isinstance(value, list): return ",".join(str(v).strip() for v in value)
	return str(value)

def verify_user_password(username, password):
	"""Checks a login attempt against the stored credential. Returns (ok, error_message). Passwords are stored as argon2id hashes; legacy plaintext entries are transparently migrated on first successful login."""
	users = g.config.get("users", {}) or {}
	stored = stored_password(users.get(username, {}))
	if not stored:
		# Burn comparable argon2 time so login timing does not reveal which usernames exist.
		if PasswordHasher is not None: PasswordHasher().hash(password)
		return False, "unknown username or incorrect password"
	if PasswordHasher is None:
		log("argon2 is not installed; falling back to constant-time plaintext comparison", logging.WARNING)
		return hmac.compare_digest(stored, password), ""
	hasher = PasswordHasher()
	if stored.startswith("$argon2"):
		try:
			hasher.verify(stored, password)
			return True, ""
		except VerifyMismatchError:
			return False, "unknown username or incorrect password"
		except InvalidHashError:
			log(f"the stored password hash for user {username} is corrupt", logging.WARNING)
			return False, "unknown username or incorrect password"
	if hmac.compare_digest(stored, password):
		try:
			g.config["users"][username]["password"] = hasher.hash(password)
			g.config.write()
			log(f"migrated the stored password of user {username} to an argon2id hash")
		except Exception:
			log(f"could not migrate the stored password of user {username} to argon2id because the config file is not writable", logging.WARNING)
		return True, ""
	return False, "unknown username or incorrect password"

def parse_speech_meta(meta):
	"""Takes speech metadata such as "Sam" or "Sam<r=4 p=-2>" and returns a dictionary of parsed properties such as voice, rate, and pitch."""
	if "<" not in meta:
		return {"voice": meta}
	voice, _, params = meta.partition("<")
	result = {"voice": voice}
	params = params.rstrip(">")
	for p in params.split(" "):
		try:
			key, value = p.strip().split("=")
			if key == "r":
				result["rate"] = value
			elif key == "p":
				result["pitch"] = value
		except ValueError:
			continue
	return result

def find_provider_for_voice(voice):
	"""Searches the list of voices for a provider to send a speech request to given a voice name."""
	if not voice:
		return voice, None
	voice = voice.strip()
	user = None
	if "/" in voice: user, delim, voice = voice.partition("/")
	voice = voice.lower()
	instance = 1
	if voice[0].isdigit() and "." in voice:
		instance, delim, voice = voice.partition(".")
		instance = int(instance)
	found = 1
	for v in sorted(g.voices, key=len):
		choices = list(g.voices[v])
		for c in list(choices):
			if user and getattr(g.clients[c]["ws"], "username") != user: choices.remove(c)
		if len(choices) < 1: continue
		if re.search(r"\b" + voice + r"\b", v.lower()):
			if instance == found:
				return v, random.choice(choices)
			else:
				found += 1
	return voice, None

def voice_packet(voice):
	"""Builds the per-voice packet sent to clients. User revision 5 and up receives a dictionary carrying the provider name (used by the client to group voices into per-provider tabs); older clients keep receiving the plain voice name string."""
	provider_name = ""
	for c in g.voices[voice]:
		if "provider_name" in g.clients.get(c, {}): return {"name": voice, "provider": g.clients[c]["provider_name"]}
	return {"name": voice, "provider": provider_name}

def register_provider(client, msg):
	"""Records and logs a provider's identity from its voices packet. An unknown identity change on an existing connection is logged loudly, as impersonating another provider's identity is a strong signal of abuse."""
	provider_id, provider_name = provider_identity(msg)
	raw_name = str(msg.get("provider_name") or "")
	known = {"provider_id": provider_id, "provider_name": provider_name}
	if any(client.get(k, None) != v for k, v in known.items()):
		if raw_name and provider_name != raw_name:
			log(f"{describe_client(client)} reported a filesystem-like provider name; sanitized to {provider_name!r} (raw value: {raw_name!r})", logging.WARNING)
		if client.get("provider_name") not in [None, ""] and client.get("provider_name") != provider_name:
			log(f"{describe_client(client)} changed reported identity to provider {provider_name} (id {provider_id or 'unknown'})", logging.WARNING)
		client.update(known)
	if not client.get("logged_connection"):
		client["logged_connection"] = True
		log(f"{describe_client(client)} connected {len(msg['voices'])} voice(s), provider id {provider_id or 'unknown'}")

async def disconnect_provider(client):
	"""Closes a provider's websocket connection; the actual cleanup happens in client_handler's finally block."""
	log(f"{describe_client(client)} was kicked by the administrator", logging.WARNING)
	try: await client["ws"].close(code = 1008, reason = "kicked by administrator")
	except Exception: pass

async def block_address(address, duration):
	"""Temporarily blocks an address from connecting, and immediately kicks any current connections from it."""
	g.blocklist[address[0]] = time.time() + duration
	for c in list(g.clients.values()):
		if c.get("remote_address") and c["remote_address"][0] == address[0]:
			log(f"connection #{c['id']} from blocked address {address[0]} is being kicked", logging.WARNING)
			try: await c["ws"].close(code = 1008, reason = "address temporarily blocked")
			except Exception: pass

async def check_reconnect_flood(address):
	"""Records a completed connection from an address and applies a temporary block when the configured reconnect threshold is crossed, defending against providers that reconnect in a tight loop."""
	g.reconnect_times.setdefault(address[0], []).append(time.time())
	window = g.reconnect_flood_window
	recent = g.reconnect_times[address[0]][-g.reconnect_flood:]
	if len(recent) >= g.reconnect_flood and recent[-1] - recent[0] <= window:
		del g.reconnect_times[address[0]]
		log(f"blocking {address[0]} for {g.reconnect_block} seconds: {g.reconnect_flood} reconnects within {window} seconds", logging.WARNING)
		await block_address(address, g.reconnect_block)
		return True
	return False

async def handle_speech_request(client, request, id=""):
	"""Processes and dispatches each speech request line to the appropriate voice provider."""
	if "speech_sequence" not in client or id:
		client["speech_sequence"] = 0
	if id:
		id = "_" + id
	if isinstance(request, str):
		request = [request]
	for line in request:
		raw_meta, _, text = line.partition(": ")
		if not text.strip():
			await client["ws"].send(json.dumps({"warning": f"no text found in line {line}"}))
			continue
		meta = parse_speech_meta(raw_meta)
		if "voice" not in meta:
			await client["ws"].send(json.dumps({"warning": f"failed to parse voice meta {raw_meta}"}))
			continue
		meta["voice"], provider = find_provider_for_voice(meta["voice"])
		if not provider:
			await client["ws"].send(json.dumps({"warning": f"failed to find provider for {meta['voice']}"}))
			continue
		provider = g.clients[provider]["ws"]
		client["speech_sequence"] += 1
		meta.update({"text": text, "id": f"{client['id']}{id}_{client['speech_sequence']}"})
		await provider.send(json.dumps(meta))
		g.speech_requests[meta["id"]] = (client, provider)

async def on_message(ws, client, message):
	"""Handles incoming WebSocket messages."""
	if isinstance(message, bytes):
		meta_len = int.from_bytes(message[:2], "little")
		meta = message[2:meta_len+2].decode()
		if meta.startswith("{"): meta = json.loads(meta)
		else: meta = {"id": meta}
		if meta["id"] in g.speech_requests: 
			await g.speech_requests[meta["id"]][0]["ws"].send(message)
			del g.speech_requests[meta["id"]]
		return
	try:
		msg = json.loads(message)
	except json.JSONDecodeError:
		return
	if "provider" in msg and "voices" in msg:
		if msg["provider"] < g.provider_rev:
			await ws.send(json.dumps({"error": f"must be revision {g.provider_rev} or higher"}))
			return
		register_provider(client, msg)
		gained_voice = False
		for v in msg["voices"]:
			if v in g.voices:
				g.voices[v].append(client["id"])
			else:
				g.voices[v] = [client["id"]]
				gained_voice = True
		if gained_voice:
			await notify_all_clients({"voices": [voice_packet(v) for v in g.voices]}, [client["id"]])
	elif "provider" in msg and "status" in msg and "id" in msg and msg["id"] in g.speech_requests:
		await g.speech_requests[msg["id"]][0]["ws"].send(message)
		if "abort" in msg and msg["abort"]: del g.speech_requests[msg["id"]]
	elif "user" in msg:
		if msg["user"] < g.user_rev:
			await ws.send(json.dumps({"error": f"must be revision {g.user_rev} or higher"}))
			return
		if "request" in msg:
			await handle_speech_request(client, msg["request"], str(msg.get("id", "")))
		elif "command" in msg:
			if msg["command"] == "abort":
				for req_id in list(g.speech_requests):
					req = g.speech_requests[req_id]
					if req[0]["ws"] == ws:
						await req[1].send(json.dumps({"abort": req_id}))
						del(g.speech_requests[req_id])
		else:
			await ws.send(json.dumps({"voices": [voice_packet(v) for v in g.voices]}))

async def notify_all_clients(data, ignore_list = []):
	"""Broadcasts a message to all connected clients."""
	if g.clients:
		await asyncio.gather(*[client["ws"].send(json.dumps(data)) for client in g.clients.values() if not client["id"] in ignore_list])

async def on_client_disconnect(ws, client_id):
	"""Handles client disconnections, updating voice providers and speech requests as needed."""
	try:
		lost_voice = False
		for v in list(g.voices):
			if client_id in g.voices[v]:
				while client_id in g.voices[v]: g.voices[v].remove(client_id)
				if len(g.voices[v]) < 1:
					del g.voices[v]
					lost_voice = True
		if lost_voice: await notify_all_clients({"voices": list(g.voices)}, [client_id])
		for r in list(g.speech_requests):
			if g.speech_requests[r][1] == ws:
				await g.speech_requests[r][0]["ws"].send(json.dumps({"warning": f"provider servicing request {r} disappeared", "request_id": r}))
			if g.speech_requests[r][0]["ws"] == ws or g.speech_requests[r][1] == ws:
				del g.speech_requests[r]
	except websockets.exceptions.ConnectionClosedOK: pass
	finally:
		client = g.clients_by_ws.get(ws)
		if client:
			log(f"{describe_client(client)} disconnected")
			if "provider_name" in client and not client.get("kicked") and getattr(ws, "close_code", None) not in (1000, 1008):
				# The provider did not disconnect gracefully (1000) and was not kicked by us (1008); count it toward reconnect flood detection.
				await check_reconnect_flood(client["remote_address"])
			g.clients_by_ws.pop(ws, None)
	# Sweep expired state so memory stays bounded: dead sessions, stale login-form tokens and aged login-failure records.
	now = time.time()
	for token in [t for t, s in g.sessions.items() if s["expires"] < now]: del g.sessions[token]
	for ip in [ip for ip, e in g.login_page_csrf.items() if now - e[1] > 600]: del g.login_page_csrf[ip]
	for ip in [ip for ip, t in g.login_attempts.items() if not t or now - t[-1] > g.login_rate_window]: del g.login_attempts[ip]

class web_send:
	"""Helper class for STAR's tiny frontend API that allows it to be able to work with existing infrastructure."""
	def __init__(self, connection): self.connection = connection
	async def __call__(self, message):
		"""So that the little HTTP API can be added without altering most of the coagulator's code, we just monkeypatch the connection.send method in the below connection_request_handler function so that the existing infrastructure just continues to work. This is the patched send function."""
		if isinstance(message, str):
			self.connection.response_mime = "application/json"
			self.connection.response_extension = ""
			self.connection.response = message
		elif isinstance(message, bytes):
			meta_len = int.from_bytes(message[:2], "little")
			meta = message[2:meta_len+2].decode()
			if meta.startswith("{"): meta = json.loads(meta)
			else: meta = {"id": meta}
			self.connection.response_extension = meta.get("extension", "wav")
			self.connection.response_mime = mimetypes.guess_type(f"synthesized.{self.connection.response_extension}")[0]
			self.connection.response = audio = message[meta_len + 2:]
def make_http_response(connection, status, mime, body):
	"""The websockets API for http headers is a bit bulky, we need a helper function to set up a response that may be either text or binary. HTML and JSON responses are marked no-store so signed-in pages and admin data never linger in shared caches, and everything gets nosniff."""
	if isinstance(body, str): body = body.encode()
	r = connection.respond(status, "")
	del(r.headers["Content-Type"])
	del(r.headers["Content-Length"])
	r.headers.update({"Content-Length": len(body), "Content-Type": mime, "X-Content-Type-Options": "nosniff"})
	if mime in ("text/html", "application/json"): r.headers["Cache-Control"] = "no-store"
	r.body = body
	return r

def set_session_cookie(response, token, clear = False):
	"""Attaches the session cookie to a response. The cookie is HttpOnly (invisible to JavaScript, which also neutralizes any future XSS cookie theft), SameSite=Strict (browsers refuse to send it on cross-site requests, the primary CSRF defense) and scoped to this server's path only."""
	cookie = http.cookies.SimpleCookie()
	cookie["star_session"] = token
	morsel = cookie["star_session"]
	morsel["path"] = "/"
	morsel["httponly"] = True
	morsel["samesite"] = "Strict"
	if clear: morsel["expires"] = "Thu, 01 Jan 1970 00:00:00 GMT"
	response.headers["Set-Cookie"] = morsel.OutputString()
	return response

def render_login(connection, error = "", notice = "", status = 200, csrf_token = None):
	"""Renders the sign-in page. Each visit issues a fresh CSRF token bound to the visitor's address and valid for ten minutes, so login submissions cannot be forged or replayed from elsewhere."""
	address = connection.remote_address or ("", 0)
	token = csrf_token if csrf_token is not None else new_login_csrf(address)
	with open(os.path.join(os.path.dirname(__file__), "coagulator_login.html"), "r") as f: page = f.read()
	page = page.replace("{{error}}", error).replace("{{notice}}", notice).replace("{{csrf}}", token)
	return make_http_response(connection, status, "text/html", page)

def new_login_csrf(address):
	token = secrets.token_urlsafe(32)
	g.login_page_csrf[address[0]] = (token, time.time())
	return token

def login_redirect(connection, error_code = ""):
	"""Sends the browser back to a clean /login URL. Submissions are never re-rendered from their query string, so the attempted password does not linger in the address bar or history; failures carry only a non-secret error code."""
	r = connection.respond(303, "")
	r.headers["Location"] = "/login" + (f"?error={error_code}" if error_code else "")
	return r

async def login_request_handler(connection, query):
	"""Serves the sign-in form and processes submissions. On success a random server-side session is created and its token handed over in an HttpOnly cookie; failed attempts are rate limited per address."""
	address = connection.remote_address or ("", 0)
	args = urllib.parse.parse_qs(query.partition("#")[0])
	if not args: return render_login(connection)
	if "error" in args:
		messages = {"invalid": "unknown username or incorrect password", "expired": "your sign-in form expired; please try again", "rate": "too many failed sign-in attempts from your address; try again later"}
		return render_login(connection, error = messages.get(args["error"][0], ""))
	wait = check_login_rate(address)
	if wait:
		log(f"rate limited a web login attempt from {address[0]}", logging.WARNING)
		return login_redirect(connection, "rate")
	username = args.get("username", [""])[0].strip()
	password = args.get("password", [""])[0]
	expected = g.login_page_csrf.get(address[0])
	if not expected or expected[0] != args.get("csrf", [""])[0] or time.time() - expected[1] > 600:
		return login_redirect(connection, "expired")
	ok, error = verify_user_password(username, password)
	if not ok:
		record_login_failure(address)
		log(f"failed web login for user {username or '(blank)'} from {address[0]}", logging.WARNING)
		return login_redirect(connection, "invalid")
	clear_login_failures(address)
	g.login_page_csrf.pop(address[0], None)
	session_token = secrets.token_urlsafe(32)
	g.sessions[session_token] = {"username": username, "expires": time.time() + g.session_lifetime, "csrf": secrets.token_urlsafe(32)}
	log(f"user {username} signed in to the web frontend from {address[0]}")
	r = connection.respond(303, "")
	r.headers["Location"] = "/"
	return set_session_cookie(r, session_token)

def logout_request_handler(connection):
	"""Destroys the visitor's server-side session and clears the cookie."""
	token = parse_cookies(connection).get("star_session")
	if token: g.sessions.pop(token, None)
	r = connection.respond(303, "")
	r.headers["Location"] = "/"
	return set_session_cookie(r, "", clear = True)

async def connection_request_handler(connection, request):
	"""Called by the websockets framework upon each http connection. WebSocket handshakes keep HTTP basic authentication; the web frontend instead uses the /login session flow, and admin pages/actions additionally require membership of the admin_users list."""
	if "upgrade" in request.headers:
		auth_failure = await g.authorize(connection, request) if not g.authless else None
		if auth_failure: return auth_failure
		return # This is a websocket connection
	#Otherwise, a very simple http API/web frontend is available,
	if "http_frontend" in g.config and not g.config.as_bool("http_frontend"): return # unless it's been disabled.
	path, delim, query = request.path.partition("?")
	if path == "/login": return await login_request_handler(connection, query)
	if path == "/logout": return logout_request_handler(connection)
	logged_in = session_username(connection)
	if path == "/":
		# The admin section ships with the page but starts hidden; it is only un-hidden for signed-in members of admin_users, and hides itself quietly if a request to /providers ever fails.
		admin = logged_in in admin_users()
		with open(os.path.join(os.path.dirname(__file__), "coagulator_index.html"), "r") as f: webpage = f.read().replace("{{username}}", logged_in or "visitor").replace("{{voicecount}}", str(len(g.voices))).replace("{{admin_hidden}}", "" if admin else " style=\"display:none;\"").replace("{{csrf}}", g.sessions[parse_cookies(connection)["star_session"]]["csrf"] if admin else "").replace("{{auth_controls}}", f'<a href="/logout">Sign out {logged_in}</a>' if logged_in else '<a href="/login">Sign in</a>')
		return make_http_response(connection, 200, "text/html", webpage)
	elif path == "/voices": return make_http_response(connection, 200, "application/json", json.dumps({"voices": [voice_packet(v) for v in g.voices]}))
	elif path == "/synthesize":
		args = urllib.parse.parse_qs(query.partition("#")[0])
		if not args or not "voice" in args and not "text" in args: return connection.respond(400, "missing voice or text argument")
		connection.send = web_send(connection)
		connection.response = b""
		voice = args["voice"][0].partition(":")[0] if "voice" in args and args["voice"] else ""
		params = []
		for arg in args:
			if arg in ["voice", "text"]: continue
			params += f"{arg}={args[arg]}"
		if voice:
			if params: voice += "<" + (" ".join(params)) + ">"
			voice += ": "
			g.next_web_id += 1
		await handle_speech_request({"ws": connection, "id": g.next_web_id}, f"{voice}{args['text'][0]}")
		while not connection.response:
			await asyncio.sleep(0.1)
		if isinstance(connection.response, str): return make_http_response(connection, 400, connection.response_mime, connection.response)
		r = make_http_response(connection, 200, connection.response_mime, connection.response)
		r.headers["content-disposition"] = f'inline; filename="speech{int(time.time())}.{connection.response_extension}"'
		return r
	elif path in ("/providers", "/kick", "/unblock"):
		if admin_endpoints_enabled() and admin_authorized(connection): return await admin_request_handler(path, query, connection)
		if path == "/providers" and admin_endpoints_enabled():
			# Signed-in non-admins get an explicit answer; everyone else gets the generic 404 so the endpoints are not advertised.
			if logged_in: return make_http_response(connection, 403, "application/json", json.dumps({"error": "the administration section requires an administrator account"}))
			if session_cookie_present(connection): return make_http_response(connection, 401, "application/json", json.dumps({"error": "please sign in again"}))
		return connection.respond(404, "not found")
	else: return connection.respond(404, "not found")

def is_loopback_request(connection):
	"""True when an HTTP request originates from the same machine the coagulator is running on. Used to let the local administrator reach the admin endpoints when the coagulator has no configured users at all (such as --authless local setups)."""
	address = connection.remote_address
	return bool(address) and address[0] in ("127.0.0.1", "::1")

def admin_authorized(connection):
	"""Decides whether an HTTP request may use the admin endpoints. Signed-in members of the admin_users list always qualify; when the coagulator has no configured users at all (for example under --authless), requests from the local machine qualify so the owner still has local admin control. Signed-in users who are not on the admin list never qualify."""
	username = session_username(connection)
	if username: return username in admin_users()
	if not list(g.config.get("users", {}) or {}): return is_loopback_request(connection)
	return False

async def admin_request_handler(path, query, connection):
	"""Handles the /providers, /kick and /unblock HTTP endpoints used to inspect and manage provider connections. They are reserved for signed-in members of the admin_users list, never to anonymous visitors, and additionally require a valid CSRF token on state-changing actions."""
	if path == "/providers":
		return make_http_response(connection, 200, "application/json", json.dumps({
			"providers": [{"id": c["id"], "name": c.get("provider_name", ""), "provider_id": c.get("provider_id", ""), "address": c["remote_address"][0] if c.get("remote_address") else "", "port": c["remote_address"][1] if c.get("remote_address") else 0, "connected_at": c.get("connected_at", 0), "voices": [v for v in g.voices if c["id"] in g.voices[v]]} for c in g.clients.values() if "provider_name" in c],
			"log": [{"time": e["time"], "message": e["message"]} for e in g.connection_log],
			"blocked": {k: round(v - time.time()) for k, v in g.blocklist.items() if v > time.time()},
		}))
	if path == "/kick":
		args = urllib.parse.parse_qs(query)
		return await admin_action(connection, args, kick = True)
	if path == "/unblock":
		args = urllib.parse.parse_qs(query)
		return await admin_action(connection, args, kick = False)
	return connection.respond(404, "not found")

async def admin_action(connection, args, kick = True):
	"""Implements /kick (by provider connection id or stable provider_id) and /unblock (by IP address), including the admin feedback log messages. State-changing requests must present the admin session's CSRF token."""
	session = g.sessions.get(parse_cookies(connection).get("star_session", ""))
	# The CSRF token belongs to the signed-in session. The only sessionless way in here is the local-machine rule for coagulators with no configured users at all, where there is no session to forge from; that path stays exempt.
	if session:
		if not hmac.compare_digest(args.get("csrf", [""])[0], session.get("csrf", "")):
			return make_http_response(connection, 403, "application/json", json.dumps({"error": "missing or invalid CSRF token; reload the administration section and try again"}))
	elif list(g.config.get("users", {}) or {}):
		return make_http_response(connection, 403, "application/json", json.dumps({"error": "missing or invalid CSRF token; reload the administration section and try again"}))
	if kick:
		target = args.get("id", [""])[0]
		matched = []
		for c in list(g.clients.values()):
			if not "provider_name" in c: continue
			if target in [str(c["id"]), c.get("provider_id", "")]: matched.append(c)
		if not matched: return make_http_response(connection, 404, "application/json", json.dumps({"error": f"no provider connection matching id {target}"}))
		for c in matched:
			c["kicked"] = True
			await disconnect_provider(c)
			g.reconnect_times.pop(c["remote_address"][0] if c.get("remote_address") else "", None)
		return make_http_response(connection, 200, "application/json", json.dumps({"kicked": [c["id"] for c in matched]}))
	address = args.get("address", [""])[0]
	if not address: return make_http_response(connection, 400, "application/json", json.dumps({"error": "missing address"}))
	if g.blocklist.pop(address, None):
		log(f"address {address} unblocked by the administrator")
		return make_http_response(connection, 200, "application/json", json.dumps({"unblocked": address}))
	return make_http_response(connection, 404, "application/json", json.dumps({"error": f"address {address} was not blocked"}))

async def client_handler(ws):
	"""Manages WebSocket client connections."""
	if not g.authless and ws.remote_address and is_blocked(ws.remote_address): return await ws.close(code = 1008, reason = "address temporarily blocked")
	client_id = g.next_client_id
	g.next_client_id += 1
	client = {"ws": ws, "id": client_id, "remote_address": ws.remote_address, "connected_at": time.time(), "connection_number": g.next_connection_number}
	g.next_connection_number += 1
	g.clients[client_id] = client
	g.clients_by_ws[ws] = client
	try:
		async for message in ws:
			await on_message(ws, client, message)
	except websockets.ConnectionClosed:
		pass
	except (asyncio.exceptions.CancelledError, KeyboardInterrupt):
		print("shutting down...")
		return
	except websockets.exceptions.ConnectionClosedOK: pass
	except: traceback.print_exc()
	finally:
		del(g.clients[client_id])
		await on_client_disconnect(ws, client_id)

def handle_args():
	"""Uses argparse to process and apply command line arguments."""
	p = argparse.ArgumentParser(argument_default = argparse.SUPPRESS)
	p.add_argument("--authless", action = "store_true")
	p.add_argument("--config", nargs = "?", const = "coagulator.ini")
	p.add_argument("--host", nargs = "?", const = "0.0.0.0")
	p.add_argument("--port", nargs = "?", type=int, const = 7774)
	p.add_argument("--configure", action = "store_true")
	g.args_parsed = p.parse_args(sys.argv[1:])
	g.authless = "authless" in g.args_parsed and g.args_parsed.authless
	g.do_configuration_interface = "configure" in g.args_parsed
	if "config" in g.args_parsed: g.config_filename = g.args_parsed.config
	else: g.config_filename = "coagulator.ini"
	g.config = configobj.ConfigObj(g.config_filename)
	if "host" in g.args_parsed: g.config["bind_address"] = g.args_parsed.host
	if "port" in g.args_parsed:
		if g.args_parsed.port < 1 or g.args_parsed.port > 65535: sys.exit("bind port must be between 1 and 65535")
		g.config["bind_port"] = g.args_parsed.port


def configuration():
	"""Command line based configuration interface that allows modifying users, as well as changing the bind host/port and other properties."""
	if not "users" in g.config: g.config["users"] = {}
	def useradd(username = ""):
		"""Also handles updating the password for an existing user."""
		while True:
			if not username: username = input("enter a username or leave blank to go back").strip()
			if not username: return
			if len(username) > 64:
				print("exceeded recommended username length of less than 64 characters")
				continue
			pwd = getpass.getpass(" enter password or leave blank to echo nothing and go back")
			if not pwd: return
			if not username in g.config["users"]: g.config["users"][username] = {}
			if PasswordHasher is None:
				log("argon2 is not installed; storing the password in plain text", logging.WARNING)
				g.config["users"][username]["password"] = pwd
			else:
				g.config["users"][username]["password"] = PasswordHasher().hash(pwd)
			break
		print("configuration updated")
	def usermod(username):
		while username in g.config["users"]:
			opt = input(f"options for {username}:\n1: change password\n2: delete user\nleave blank to go back")
			if not opt: return
			if not opt.isdigit():
				print("only numbers accepted")
				continue
			opt = int(opt)
			if opt == 1: useradd(username)
			elif opt == 2: userdel(username)
	def userdel(username):
		confirm = input(f"Are you sure you want to delete the user {username}? Input y for yes or anything else to cancel.")
		if confirm != "y": return
		del(g.config["users"][username])
		print("configuration updated")
	def userlist():
		while True:
			if not "users" in g.config or len(g.config["users"]) < 1:
				print("no users")
				return
			if len(g.config["users"]) != 1: print(f"There are {len(g.config['users'])} users, select one by it's number or leave blank to go back")
			else: print("There is 1 user, select it by it's number or leave blank to go back")
			for i, u in enumerate(g.config["users"]):
				print(f"{i + 1}: {u}")
			opt = input()
			if not opt: return
			if not opt.isdigit() or int(opt) < 1 or int(opt) > len(g.config["users"]):
				print("must be a valid user number")
				continue
			usermod(list(g.config["users"])[int(opt) -1])
	def toggle_http_frontend():
		value = g.config.as_bool("http_frontend") if "http_frontend" in g.config else True
		g.config["http_frontend"] = not value
		print("HTTP frontend " + ("enabled" if not value else "disabled"))
	def toggle_admin_endpoints():
		value = g.config.as_bool("admin_endpoints") if "admin_endpoints" in g.config else True
		g.config["admin_endpoints"] = not value
		print("admin endpoints " + ("enabled" if not value else "disabled"))
	def edit_admin_users():
		"""Maintains the comma-separated list of usernames allowed to sign into the admin section."""
		current = g.config.get("admin_users", "")
		print(f"Users who may sign into the admin section: {current or '(none; defaults to the first configured user)'}")
		new = input("enter a comma-separated list of usernames, or leave blank to go back").strip()
		if not new: return
		g.config["admin_users"] = ", ".join(u.strip() for u in new.split(",") if u.strip())
		print("configuration updated")
	def edit_login_rate():
		"""Tunes the per-address login failure limiter."""
		for key, prompt in (("login_rate_threshold", "how many failed sign-in attempts to allow from one address"), ("login_rate_seconds", "over how many seconds failures are counted")):
			value = input(f"{prompt} (currently {g.config.get(key, 8 if key == 'login_rate_threshold' else 60)}), leave blank to keep")
			if value and value.isdigit() and int(value) > 0: g.config[key] = value
		print("configuration updated")
	def set_var(varname, prompt, default = "", validator = None):
		data = g.config.get(varname, default)
		while True:
			new_data = input(f"{prompt} (currently {data}), leave blank to go back without modifying value")
			if not new_data: return
			validate_fail = validator(new_data) if validator else ""
			if validate_fail:
				print(validate_fail)
				continue
			g.config[varname] = new_data
			break
		print("configuration updated")
	options = [("add a user", "useradd"), ("change or delete a user", "usermod"), ("set who can sign into the admin section", "admin_users"), ("set bind address", "bindaddr"), ("set bind port", "bindport"), ("{frontend_action} HTTP frontend", "http_frontend"), ("{admin_action} admin endpoints", "admin_endpoints"), ("set login rate limiting", "login_rate"), ("save and exit", "X"), ("exit without saving", "x")]
	options_str = "Select an option, follow all input with return:\n"
	for i, o in enumerate(options):
		options_str += f"{i + 1}: {o[0]}\n"
	while True:
		try: opt = input(options_str.format(frontend_action = "enable" if "http_frontend" in g.config and not g.config.as_bool("http_frontend") else "disable", admin_action = "enable" if "admin_endpoints" in g.config and not g.config.as_bool("admin_endpoints") else "disable"))
		except EOFError: return
		if not opt: continue
		if not opt.isdigit():
			print("only digits accepted")
			continue
		opt = int(opt)
		if opt < 1 or opt > len(options):
			print(f"option {opt} out of range")
			continue
		opt = options[opt -1][1]
		if opt == "useradd": useradd()
		elif opt == "usermod": userlist()
		elif opt == "bindaddr": set_var("bind_address", "enter address to bind to", "0.0.0.0")
		elif opt == "bindport": set_var("bind_port", "enter port to bind to", 7774, lambda value: "port must be a number between 1 and 65535" if not value.isdigit() or int(value) < 1 or int(value) > 65535 else "")
		elif opt == "http_frontend": toggle_http_frontend()
		elif opt == "admin_endpoints": toggle_admin_endpoints()
		elif opt == "admin_users": edit_admin_users()
		elif opt == "login_rate": edit_login_rate()
		elif opt == "X":
			g.config.write()
			print("configuration saved")
			return
		elif opt == "x": return

async def main():
	g.speech_requests = {}
	g.voices = {}
	g.clients = {}
	g.clients_by_ws = {}
	g.connection_log = []
	g.connection_log_limit = 200
	g.blocklist = {}
	g.reconnect_times = {}
	g.next_connection_number = 1
	handle_args()
	g.reconnect_flood = int(g.config.get("reconnect_flood_threshold", g.reconnect_flood_default))
	g.reconnect_flood_window = int(g.config.get("reconnect_flood_seconds", g.reconnect_flood_window_default))
	g.reconnect_block = int(g.config.get("reconnect_block_seconds", g.reconnect_block_default))
	if g.do_configuration_interface: return configuration()
	if PasswordHasher is None: log("argon2-cffi is not installed; passwords will be compared in plain text and cannot be hashed. Run: pip install argon2-cffi", logging.WARNING)
	legacy = [u for u, v in (g.config.get("users", {}) or {}).items() if isinstance(v, dict) and stored_password(v) and not stored_password(v).startswith("$")]
	if legacy: log(f"{len(legacy)} user password(s) are still stored in plain text and will be hashed to argon2id the first time each user signs in: {', '.join(legacy)}")
	g.session_lifetime = int(g.config.get("web_session_lifetime", 86400))
	g.login_rate_threshold = int(g.config.get("login_rate_threshold", 8))
	g.login_rate_window = int(g.config.get("login_rate_seconds", 60))
	g.authorize = websockets.asyncio.server.basic_auth(check_credentials = lambda username, password: verify_user_password(username, password)[0])
	async with websockets.asyncio.server.serve(client_handler, g.config.get("bind_address", "0.0.0.0"), int(g.config.get("bind_port", 7774)), max_size = int(g.config.get("max_packet_size", 1024 * 1024 * 10)), max_queue = 4096,  process_request = connection_request_handler):
		print("Coagulator up.")
		await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print("coagulator down.")
