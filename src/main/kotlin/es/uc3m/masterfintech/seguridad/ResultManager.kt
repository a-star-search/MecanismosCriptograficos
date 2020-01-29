package es.uc3m.masterfintech.seguridad

import es.uc3m.masterfintech.seguridad.function.*

/**
 * Patron Visitor o double dispatch
 * para desacoplar la presentacion de resultados de los algoritmos de las funciones y
 * permitir a la aplicacion tratar todas las funciones uniformemente (polimorfismo)
 *
 * Se debe tener en cuenta que cada funcion genera un valor diferente, por ejemplo las de
 * validacion un booleano, cifrado y descifrado, un texto, cifrado asimetrico, claves y texto, etc.
 */
internal interface ResultManager {
  fun visit(f: HashingFunction)
  fun visit(f: HashVerificationFunction)
  fun visit(f: SymmetricCipheringFunction)
  fun visit(f: SymmetricDecipheringFunction)
  fun visit(f: AsymmetricCipheringFunction)
  fun visit(f: AsymmetricDecipheringFunction)
  fun visit(f: TimestampFunction)
  fun visit(f: TimestampVerificationFunction)
  fun visit(f: AsymmetricKeysGenerationFunction)
  fun visit(f: SigningFunction)
  fun visit(f: SigningVerificationFunction)
}