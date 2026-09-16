# Balcony

This provider wraps the Balabolka Command Line Utility (balcon.exe), providing access to all 32 bit SAPI4/SAPI5 voices on a machine. Voices are reported along with the speech engine they belong to (SAPI4, SAPI5, OneCore and similar), letting clients such as STAR group them into separate tabs per engine.

With SAPI5, rate and pitch should go from -10 to 10, with SAPI4 it's a floatingpoint.
