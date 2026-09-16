import os, re, subprocess, sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from provider import star_provider

class balcony(star_provider):
	def get_voices(self):
		"""Parses the balcon -l listing. Unindented lines are engine category headers (SAPI4, SAPI5, OneCore and similar) and each indented line below belongs to that engine; the engine is reported per voice so clients can group voices by engine."""
		raw = subprocess.run([os.path.join(os.path.abspath(os.path.dirname(__file__)), "balcon"), "-l"], shell = True, capture_output = True, text = True).stdout.split("\n")
		voices = {}
		engine = ""
		for v in raw:
			if not v.strip(): continue
			if not v.startswith(" "):
				# Headers look like "2 SAPI (SAPI4) voices" or "5 Microsoft OneCore voices"; keep the engine name only.
				engine = re.sub(r"\bvoices?\b\s*$", "", v.strip(), flags = re.IGNORECASE).strip()
				parenthetical = re.search(r"\(([^)]+)\)", engine)
				engine = parenthetical.group(1).strip() if parenthetical else re.sub(r"^\d+\s*", "", engine).strip()
				engine = re.sub(r"^Microsoft\s+", "", engine, flags = re.IGNORECASE)
				engine = re.sub(r"\s+", " ", engine)
				continue
			voice = v
			if "::" in voice: voice = voice[voice.find("::") + 3:]
			voices[voice.strip()] = {"full_name": v.strip(), "engine": engine}
		return voices

if __name__ == "__main__":
	balcony("balcony", synthesis_process = [os.path.join(os.path.abspath(os.path.dirname(__file__)), "balcon"), "-n", "{voice}", "-w", "{filename}", "-t", "{text}"], synthesis_process_rate = ["-s", "{rate}"], synthesis_process_pitch = ["-p", "{pitch}"])
