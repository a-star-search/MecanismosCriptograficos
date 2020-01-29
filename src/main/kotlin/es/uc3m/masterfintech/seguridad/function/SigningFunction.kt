package es.uc3m.masterfintech.seguridad.function

import es.uc3m.masterfintech.seguridad.ResultManager
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature

/**
 * Firma usando DSA
 */
internal class SigningFunction(val sInputFile: String): Function() {
  val signature: BigInteger
  val bPublic: ByteArray
  val bPrivate: ByteArray

  init {
    val keyGen = KeyPairGenerator.getInstance("DSA")
    val random = SecureRandom.getInstance("SHA1PRNG")
    keyGen.initialize(1024, random)
    val keyPair = keyGen.generateKeyPair()
    val privateKey = keyPair.private
    val publicKey = keyPair.public

    val dsa = Signature.getInstance("SHA1withDSA")
    dsa.initSign(privateKey)

    val bytesToSign = readFileContentsAsBytes(sInputFile)
    dsa.update(bytesToSign)
    signature = BigInteger(1, dsa.sign())
    bPublic = publicKey.encoded
    bPrivate = privateKey.encoded
  }
  override fun accept(visitor: ResultManager) = visitor.visit(this)
}