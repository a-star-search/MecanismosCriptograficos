package es.uc3m.masterfintech.seguridad.function

import es.uc3m.masterfintech.seguridad.ResultManager
import javax.crypto.Cipher.*
import javax.crypto.spec.SecretKeySpec
import kotlin.text.Charsets.UTF_8
import javax.crypto.spec.IvParameterSpec

/**
 * Se utiliza AES con modo de operacion de encadenado de bloques (CBC)
 *
 * AES es un algoritmo de cifrado de bloques de 128 bits que acepta claves de 128, 192 y 256 bits.
 */
internal class SymmetricCipheringFunction(sInputFile: String, pass: String): Function() {
  /** Expresado como cadena de hexadecimales */
  val cipheredText: String

  init {
    val bText = readFileContentsAsBytes(sInputFile)
    val bPass = pass.toByteArray(UTF_8)
    val ciphered = cipher(bText, bPass)
    cipheredText = bytesToHexString(ciphered)
  }

  private fun cipher(bText: ByteArray, bPass: ByteArray): ByteArray {
    val cipher = getInstance(ALGORITHM_MODE_PADDING)!!
    val secretKeySpec = SecretKeySpec(bPass, ALGORITHM)
    cipher.init(ENCRYPT_MODE, secretKeySpec, IV_SPEC)
    return cipher.doFinal(bText)
  }

  override fun accept(visitor: ResultManager) = visitor.visit(this)

  companion object {
    const val ALGORITHM = "AES"
    const val ALGORITHM_MODE_PADDING = "AES/CBC/PKCS5Padding"
    val IV_SPEC = IvParameterSpec(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
  }
}