# Experimental BAP sensor 4.2.0

The Azul Android APK 7.4.1 contains Akamai BMP SDK 4.0.5. Its Java layer passes
`4.2.0` as the first sensor field to the native builder. This package adapts the
existing 4.2.1 generator to that version. Instrumentation of Azul 7.6.0 showed
that `-115` follows `-112`, `-172` contains four integers when root/Appium
checks are clear, and the JavaScript signal starts with `buildId`,
`screenWidth`, and `cpuABI`. Those observations are reflected here.

This remains **experimental**. The generator encrypts its own payload
consistently, and a sensor built with fresh HTTP DCI and JavaScript signals
was accepted by an Azul Android availability request in three local controls
on 2026-09-25. Those controls used a separate Android phone as the HTTP
transport. The same complete flow sent from a desktop IP received HTTP 403,
and a generator sensor without the fresh DCI/JS signals received HTTP 403 even
through the phone. Thus, acceptance depends on more than the seven-part
format. A native SDK-generated sensor also received HTTP 403 from the desktop
IP during the paired control.

`jsSignals` and `cprSignal` in `BuildSensorPairs` must be populated by a caller
for the demonstrated path. The package does not fetch DCI, execute the remote
challenge, or provide an HTTP transport itself. Compatibility across IPs,
devices and sessions remains unverified; the native encryption and key material
have not been byte-compared with this generator.
