package es.uc3m.masterfintech.seguridad

/**
 * Modo de operacion
 */
enum class Mode(val code: String) {
  SYMMETRIC_CIPHERING("cs"),
  SYMMETRIC_DECIPHERING("ds"),
  HASHING("h"),
  HASH_VERIFICATION("vh"),
  ASYMMETRIC_KEY_GENERATION("gca"),
  ASYMMETRIC_CIPHERING("ca"),
  ASYMMETRIC_DECIPHERING("da"),
  TIMESTAMPING("ts"),
  TIMESTAMPING_VERIFICATION("vts"),
  SIGNING_VERIFICATION("vs"),
  SIGNING("s")
}