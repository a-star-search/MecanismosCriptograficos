package es.uc3m.masterfintech.seguridad.function

import es.uc3m.masterfintech.seguridad.ResultManager
import es.uc3m.masterfintech.seguridad.function.SymmetricCipheringFunction.Companion.ALGORITHM
import es.uc3m.masterfintech.seguridad.function.SymmetricCipheringFunction.Companion.ALGORITHM_MODE_PADDING
import es.uc3m.masterfintech.seguridad.function.SymmetricCipheringFunction.Companion.IV_SPEC
import javax.crypto.Cipher.*
import javax.crypto.spec.SecretKeySpec
import kotlin.text.Charsets.UTF_8

/**
 * El texto del fichero de entrada debe ser una cadena de hexadecimales
 */
internal class SymmetricDecipheringFunction(sInputFile: String, pass: String): Function() {
  val clearText: String

  init {
    val cipheredText = readFileContents(sInputFile)
    val bCipheredText = hexStringToBytes(cipheredText)
    val bPass = pass.toByteArray(UTF_8)
    val deciphered = decipher(bCipheredText, bPass)
    clearText = String(deciphered, UTF_8)
  }

  private fun decipher(bCipheredText: ByteArray, bPass: ByteArray): ByteArray {
    val cipher = getInstance(ALGORITHM_MODE_PADDING)!!
    val secretKeySpec = SecretKeySpec(bPass, ALGORITHM)
    cipher.init(DECRYPT_MODE, secretKeySpec, IV_SPEC)
    return cipher.doFinal(bCipheredText)!!
  }

  override fun accept(visitor: ResultManager) = visitor.visit(this)
}