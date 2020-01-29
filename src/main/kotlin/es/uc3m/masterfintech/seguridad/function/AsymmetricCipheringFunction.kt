package es.uc3m.masterfintech.seguridad.function

import es.uc3m.masterfintech.seguridad.ResultManager
import org.bouncycastle.asn1.x509.ObjectDigestInfo.publicKey
import java.io.File
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyFactory
import java.security.KeyPair
import javax.crypto.Cipher
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import javax.xml.bind.DatatypeConverter.printHexBinary
import java.security.spec.RSAPublicKeySpec
import kotlin.text.Charsets.UTF_8

/**
 * Cifra una contrasena (pequeña cadena de caracteres) con una clave pública RSA
 *
 * RSA solo es adecuado para cifrar cortas cadenas de caracteres, como en este caso contraseñas
 */
internal class AsymmetricCipheringFunction(rsaPublicKeyFile: String, password: String) : Function() {
  /** password cifrado, representado como cadena de hexadecimales */
  val rsaCipheredPassword: String

  init {
    //solo deberia usarse para ficheros pequeños
    val lines = Files.readAllLines(Paths.get(rsaPublicKeyFile))!!
    val sModulus = lines[5]!! //6th line
    val sExponent = lines[7]!! //8th line
    val modulus = BigInteger(sModulus)
    val exponent = BigInteger(sExponent)
    val keyFactory = KeyFactory.getInstance(ALGORITHM)!!
    val publicKeySpec = RSAPublicKeySpec(modulus, exponent)
    val key = keyFactory.generatePublic(publicKeySpec) as RSAPublicKey

    val bText = password.toByteArray(UTF_8)

    val cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")!!
    cipher.init(Cipher.ENCRYPT_MODE, key)

    val bCiphered = cipher.doFinal(bText)!!
    rsaCipheredPassword = bytesToHexString(bCiphered)
  }

  override fun accept(visitor: ResultManager) = visitor.visit(this)

  companion object {
    const val ALGORITHM = "RSA"

    fun generateKeyPair(): KeyPair {
      val keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM)!!
      keyPairGenerator.initialize(1024)
      return keyPairGenerator.generateKeyPair()!!
    }
  }
}
