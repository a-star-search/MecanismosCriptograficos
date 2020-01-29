package es.uc3m.masterfintech.seguridad.function

import es.uc3m.masterfintech.seguridad.ResultManager
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

/**
 * Genera un par de claves RSA
 */
internal class AsymmetricKeysGenerationFunction: Function() {
  val publicKey: RSAPublicKey
  val privateKey: RSAPrivateKey
  /**
   * Como cadena. Es importante mantener el formato puesto que otras funciones toman como entrada
   * la representacion como cadena de las claves que se hace en este algoritmo de generacion de claves.
   */
  val sPublicKey: String
  /**
   * Como cadena. Es importante mantener el formato puesto que otras funciones toman como entrada
   * la representacion como cadena de las claves que se hace en este algoritmo de generacion de claves.
   */
  val sPrivateKey: String

  init {
    val keyPair = AsymmetricCipheringFunction.generateKeyPair()
    publicKey = keyPair.public as RSAPublicKey
    privateKey = keyPair.private as RSAPrivateKey

    val publicAlgorithm = publicKey.algorithm
    val publicFormat = publicKey.format
    val publicModulus = publicKey.modulus!!
    val publicExponent = publicKey.publicExponent!!
    val privateModulus = privateKey.modulus!!
    val privateExponent = privateKey.privateExponent!!
    sPublicKey = "Algorithm $publicAlgorithm" +
            "\nFormat $publicFormat" +
            "\n\nPublic key" +
            "\n\tModulus\n$publicModulus" +
            "\n\tExponent\n$publicExponent"
    sPrivateKey = "Private key\n\tModulus\n$privateModulus\n\tExponent\n$privateExponent"
  }
  override fun accept(visitor: ResultManager) = visitor.visit(this)
}