final Map<String, int> TLS_EXT = {
  "SERVER_NAME": 0x0000,
  "SUPPORTED_GROUPS": 0x000A,
  "SIGNATURE_ALGORITHMS": 0x002D,
  "KEY_SHARE": 0x0033,
  ...
};

final Map<String, ExtensionDefinition> exts = {
  "SERVER_NAME": ExtensionDefinition( encode: ..., decode: ... ),
  ...
};

// Reverse lookup
String extNameByCode(int code) { ... }