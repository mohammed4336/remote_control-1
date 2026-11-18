# Remote Control Agent v1.0.1

## Changes
- Add automatic Agent update checks against the latest stable GitHub Release.
- Verify downloaded Agent binaries against the release SHA-256 manifest.
- Preserve the previous executable during replacement and attempt rollback if the updated process exits immediately.
- Keep the user's agent_config.json alongside the executable.
- Add a 60 FPS target to stream quality controls.
- Persist adaptive stream width and quality changes.
- Serve the latest Agent release from the website download route.

## Validation
The Windows release workflow compiles the Python sources, verifies dependencies, builds the one-file executable, and creates the update manifest. Real-device remote-control, audio, latency, and updater installation tests are still required after the release build.
