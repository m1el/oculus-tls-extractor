# Oculus TLS extractor

The purpose of this code is to extract TLS keys from a running `OVRServer_x64.exe`, that sends some data to the mothership over TLS.

For details, please read the [accompanying post](http://m1el.github.io/oculus-tls-extract/)

**Note:** this codebase is only intended for experimentation and documentation of reverse engineering.
Using this code may cause system instability and crash your Oculus Runtime.

## Usage

To use `injector.exe` as a debugger for `OVRServer_x64.exe`, you can use `gflags` or `regedit`.
`injector.exe` expects path to `OVRServer_x64.exe` as its first argument, the rest of the arguments will be passed through to `OVRServer_x64.exe`.

By default, `injectee.dll` will log TLS keys into `ssl_keylog.txt` near its own location.
To override secret key log location, set system environment variable `SSLKEYLOGFILE`.
Keylog format is expected to be compatible with [NSS Keylog Format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format).
