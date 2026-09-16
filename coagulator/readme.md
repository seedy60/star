# STAR coagulator
The coagulator is what is responsible for networking all shared voices together with any connected user clients, the bridge between the various parts of STAR as it were.

Though a compiled coagulator.exe binary is included with the full STAR client package for windows, that is mostly used for STAR's local usage features and might not be the most convenient if you are trying to host a STAR coagulator for your team. Particularly, no support will be provided for anyone trying to run coagulator.exe through wine. Instead, it's probably best to run the coagulator from source at least on all platforms that aren't windows at this time.

The coagulator can run on windows, MacOS or Linux provided that the host machine contains a relatively modern version of python3 (3.11 works on my server, for example).

## Command line arguments
The coagulator processes a couple of command line arguments that are very useful to know about.
* --configure: This opens a terminal based configuration interface where it is possible to add and modify/delete users, choose which usernames may sign into the admin section, tune the login rate limit, as well as alter the host and port that the server binds to and toggle the HTTP frontend and admin endpoints. At this time you'll need to restart the coagulator after making any config changes here.
* --config /path/to/config.ini: This allows you to specify a custom location for the configuration file, by default it is just coagulator.ini along side coagulator.py/.exe.
* --authless: This temporarily disables all password authentication on the coagulator, use with care! Coagulators with no password authentication could lead to anything from DDoS attacks to voices being used nonconsentually and/or in ways that violates their license agreements, including but not limited to wasted quotas for cloud voices if someone finds your coagulator and spams it.
* --host `<host>`, --port `<port>`: Allows you to temporarily change the host and port that the coagulator binds to. For a more permanent change, use the --configure option instead.

## Windows quickstart
If you have a windows server and/or can forward ports on your home windows machine, this is the one instance where using the precompiled coagulator.exe program might be useful. You can simply press shift+f10 on the coagulator.exe file and click create shortcut, then paste that shortcut into the "shell:startup" folder for the coagulator to run every time the system boots. However, an undesireable terminal window might appear as a result of doing it this way.

Assuming you have python 3.12 or later and git installed or have [downloaded the source code](https://github.com/samtupy/star/archive/refs/heads/main.zip), you can open a command prompt up to the source code's location and do the following:
1. Create a python virtual environment: `python -m venv venv`, and activate it, `venv\scripts\activate` to isolate all modules.
2. Install the requirements, `pip install -r coagulator/requirements.txt`
3. Configure the coagulator, `python coagulator/coagulator.py --configure`

The above steps only need to be repeated once. After that, you can open a command prompt and run the coagulator with the single command `venv\scripts\python coagulator\coagulator.py` or if you do activate the virtual environment, simply `python coagulator/coagulator.py`

If you'd like to get rid of the terminal window, you can run  the coagulator using the pythonw command instead of just python, for example `pythonw coagulator/coagulator.py`

## MacOS and Linux quickstart
The instructions on MacOS and Linux are pretty much the same. Similar to above, you should clone the github repository or download the sourcecode as a zip, and cd to that directory in a terminal.
1. Create a virtual environment, `python3 -m venv venv` and activate it, `source venv/bin/activate` in this case. You might get an error on Linux about needing to install the python3-venv package, if so you should follow that instruction and use apt-get or your package manager of choice to install the package it indicates before executing the venv creation command again.
2. Install the requirements, `pip install -r coagulator/requirements.txt`
3. Configure the coagulator, `python coagulator/coagulator.py --configure`

Again when you are just running the coagulator in the future, you can skip the venv activation if you like by running `venv/bin/python coagulator/coagulator.py`

## Linux systemd unit
On linux, a systemd .service file is provided if you want the coagulator you are hosting to run automatically when your server reboots.

1. You will need to modify starserver.service in the coagulator directory of the repository and make it point to an existing user on your system. That user should have the star repository cloned in their home directory, or else you can modify the .service file further as you see fit if you'd like it somewhere else.
2. Copy the modified starserver.service file to /etc/systemd/system
3. Configure the coagulator with the same command as usual.
4. Run `sudo systemd start starserver` to bring the server up, `sudo systemd stop starserver` to bring the server down, `sudo systemctl enable starserver` to make the server auto start on boot, or `sudo systemctl disable starserver` to prevent the auto start.

If you want to change the coagulator's configuration, such as to add a user, you can run the configuration command at any time. However after saving the configuration, you must then run `sudo systemctl restart starserver` for the configuration changes to take effect.

## Web interface and API
By default, STAR coagulators include a very simple web frontend which allows basic voice synthesis directly from a browser or with a tiny API.

So long as coagulator_index.html and coagulator_login.html are in the same directory as coagulator.py and so long as this feature has not been disabled in the configuration, it is possible to browse to http://coagulator:port to access a tiny web frontend that allows you to preview voices and synthesize text to them. The synthesis API described below is open to anyone who can reach the server (disable the frontend with http_frontend = False if you do not want this); the Administration section, however, requires signing in with an administrator account via the /login page.

Administrator access is protected by a proper session login: passwords are verified against argon2id hashes, sign-in attempts are rate limited per address, session cookies are HttpOnly, and all admin actions require a per-session CSRF token.

While the web frontend doesn't natively support rendering to disk, it is possible to fetch the audio data for a line of synthesis using the little API offered by this web service which is self-described on the page. For example, the following is a cool curl command that will speak some text to the ffplay utility if that is installed.

```curl -s "http://domain.com:7774/synthesize?voice=microsoft+sam&text=this+is+a+test!"|ffplay - -showmode 0 -loglevel -8 -autoexit```

If you wish to disable this frontend for your coagulator, you can either set http_frontend = False in coagulator.ini, or set the option to your desired value using the coagulator's --configure argument. If this is disabled and someone browses to the page via http, they will get an error message about not being able to upgrade to a websocket connection, which was what happened before this frontend was introduced.

## Identifying and managing providers
The coagulator keeps an in-memory log of connection events (providers connecting, disconnecting, being kicked and being blocked), and every provider identifies itself with a name plus a stable, random provider ID that persists across restarts of that provider. This makes it possible to tell exactly which provider connected, from where, and to act on malfunctioning or malicious ones.

When authentication is enabled (that is, the coagulator is not running --authless), the web frontend gains an Administration section where you can:
* See every connected provider with its name, connection ID, stable provider ID, source address and port, voice count, and the time it connected.
* Kick any provider, which immediately disconnects it (providers configured to reconnect will simply come back unless you deal with the host itself).
* Unblock addresses that were automatically blocked for reconnect flooding.
* Read the recent connection log.

The same features are available as JSON HTTP endpoints for scripting:
* GET /providers: Returns the connected providers, the recent connection log and any currently blocked addresses.
* GET /kick?id=<connection id or provider id>: Kicks one or all connections matching the given id. Kicking by the stable provider ID matches every connection made by that provider installation, even if it reconnected and moved to a different port.
* GET /unblock?address=<ip>: Removes an address from the blocklist.

These endpoints are only served when the HTTP frontend is enabled, and they require signing in through /login with a username that appears in the admin_users option (a comma-separated list in coagulator.ini, editable via --configure). If admin_users is not set, it defaults to the first configured user, so existing setups keep working. Signed-in users who are not on the list can use the rest of the frontend but see no Administration section and receive 403 responses from these endpoints. As a special case, a coagulator with no configured users at all (such as a local --authless setup) lets requests from the same machine use the admin endpoints, so the owner always retains local control. The endpoints can be disabled entirely with admin_endpoints = False.

Sessions live for web_session_lifetime seconds (default 86400, one day) and end when you follow the Sign out link or restart the coagulator. Failed sign-in attempts are rate limited: by default 8 failures within 60 seconds from one address blocks further attempts until the window elapses; tune with login_rate_threshold and login_rate_seconds. Both successful and failed sign-ins are recorded in the connection log with the source address.

Providers that disconnect and reconnect rapidly are blocked automatically: by default 8 reconnects within 60 seconds from the same address earns it a 300 second ban during which no new connections from that address are accepted, and any existing connections from it are kicked. The thresholds can be tuned in coagulator.ini via reconnect_flood_threshold, reconnect_flood_seconds and reconnect_block_seconds. Note that this counting is based on ungraceful disconnects and failed reconnect attempts; a provider that shuts down cleanly or gets kicked by you is never penalized, and kicking a provider clears any flood count it may have accumulated.

This system identifies provider *installations*, not humans: anyone who obtains your coagulator's URI (including its password) can connect and will appear with whatever name their provider reports. For true accountability, keep your coagulator's credentials only among people you trust, and give each person their own user account, since users show up in logs too.

As defense in depth, reported provider names are sanitized: filesystem paths are reduced to their final component (an unpatched provider that would have announced itself as /home/you/star/provider/polly/polly.py simply shows as polly), script extensions are stripped and control characters are removed. Whenever sanitization changes a name, the raw value is recorded in the connection log as a warning so you can still investigate, and the operator never sees raw paths in voice tabs or the admin list. A provider operator can always choose their own display name deliberately with the provider's --name flag.

## Sharing your coagulator's URI and other tips
Both the user client and STAR providers connect to your coagulator using standardized URI syntax with the WebSocket (ws) scheme. That is, a valid URI might look like ws://username:password@address:port.

So if your server has the IP address 2.3.4.5 and you host a coagulator on the default port (7774) with a user named 'joe' who has a password of 'DoNotHackMeBro', you could send joe the URI ws://joe:DoNotHackMeBro@2.3.4.5:7774 which they can just paste into the host field in their client or provider configuration.

It might be best to avoid passwords with special characters for now, as such characters need to be URL encoded making them more difficult to type in URI form. For example if a password has an @ character in it such as 'my_password@secure', the uri would look like ws://user:my_password%40secure@host:port, otherwise as you can imagine the system would get confused and think that the word secure after the first @ character was part of the address!

Passwords are stored as argon2id hashes rather than in plain text; when you add a user through --configure the password is requested with hidden input and only its hash is written to coagulator.ini. Configurations that still contain plain-text passwords (from older versions) are transparently hashed the first time each affected user signs in. This depends on the argon2-cffi package being installed; without it the coagulator warns at startup and falls back to comparing passwords in plain text, so install it before exposing a coagulator to the internet. As always, avoid reusing passwords here that you use elsewhere.
