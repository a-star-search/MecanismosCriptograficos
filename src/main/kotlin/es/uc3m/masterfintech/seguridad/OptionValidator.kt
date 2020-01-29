package es.uc3m.masterfintech.seguridad

import es.uc3m.masterfintech.seguridad.Mode.*

internal object OptionValidator {
  /**
   * Las opciones o parametros pasadas en la ejecucion del programa son incorrectas si no estan presentes todos los
   * parametros obligatorios o si no esta presente alguna combinacion necesaria de estos.
   *
   * Se devuelve un valor booleano, sin dar detalles del error concreto en los parametros.
   */
  fun validateOptions(options: ProgramOptions): Boolean =
    validateRequiredOptions(options) &&
    validateOptionsForSymmetricCipheringMode(options) &&
    validateOptionsForHashVerificationMode(options)
    //TODO: there are many more validations to do!! just in case I have time... (not required though)

  private fun validateRequiredOptions(options: ProgramOptions): Boolean =
    //the only required option for all cases turns out to be just mode
    options.mode!!.isNotEmpty()

  /** Falso si y solo si modo cifrado simetrico y opciones incorrectas */
  private fun validateOptionsForSymmetricCipheringMode(options: ProgramOptions): Boolean {
    val isSymmetricCiphering  = options.mode == SYMMETRIC_CIPHERING.code
    val isSymmetricDeciphering  = options.mode == SYMMETRIC_DECIPHERING.code
    if(!isSymmetricCiphering && !isSymmetricDeciphering)
      return true
    return options.pass.isNotEmpty()
  }

  /** Falso si y solo si modo verif resumen y opciones incorrectas */
  private fun validateOptionsForHashVerificationMode(options: ProgramOptions): Boolean {
    val isHashVerification = options.mode == HASH_VERIFICATION.code
    if(!isHashVerification)
      return true
    return options.additional.isNotEmpty()
  }
}