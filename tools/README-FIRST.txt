SDG CONNECTION TEST
===================

This tool checks whether your internet connection has trouble reaching
the SDG Space Engineers test server. It sends harmless UDP traffic
that looks like the game's own traffic and reports back what got
through.


HOW TO RUN IT
-------------
  1. Make sure you're connected to the network you want to test
     (the same Wi-Fi or wired connection you use to play).
  2. Double-click "Run-Test.cmd" in this folder.
  3. A black window opens and runs for about 3 to 4 minutes.
     DO NOT close it - it closes itself when finished.
  4. When it finishes you'll see a line like this:
            Report saved to:
              <this folder>\sdg-test-report-...json
     The report file appears RIGHT NEXT TO Run-Test.cmd in this same
     folder.
  5. Attach that .json file to your SDG support ticket.

  That's it. You're done.


WHAT'S IN THIS FOLDER
---------------------
  Run-Test.cmd       - the launcher. Double-click this.
  config.txt         - the SDG server address. Do NOT edit unless
                       SDG support tells you to.
  app\               - the test program. You don't need to open it.
  LICENSE.txt        - the MIT license this tool is shipped under.


REQUIREMENTS
------------
  - Windows 10 or Windows 11, 64-bit.
  - Outbound UDP allowed (most home connections; corporate firewalls
    may block the test).


TROUBLESHOOTING
---------------
  "Windows protected your PC" warning
      Click "More info" then "Run anyway". This bundle is unsigned;
      the SHA256 hash of the download is published on the SDG release
      page if you want to verify it before running.

  The window closes immediately
      Open a Command Prompt, drag "Run-Test.cmd" into it, and press
      Enter. The error will stay on screen for you to read or send
      to support.

  "config.txt is missing"
      Re-download the bundle from the SDG release page.


PRIVACY
-------
  The report file contains: per-port test results (round-trip time,
  packet loss, MTU), NAT type, and a REDACTED form of your public IP
  (e.g. "1.2.3.x" - the last octet is dropped). It does NOT contain
  personal files, browsing history, or anything outside this
  connection test. You can open the report in any text editor before
  sending it - it's plain JSON.
