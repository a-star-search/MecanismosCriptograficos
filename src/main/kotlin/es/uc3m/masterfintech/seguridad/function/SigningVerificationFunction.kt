package es.uc3m.masterfintech.seguridad.function

import es.uc3m.masterfintech.seguridad.ResultManager
import java.io.File
import java.math.BigInteger
import java.security.*
import java.security.spec.X509EncodedKeySpec

/**
 * Verificacion de firma DSA
 */
internal class SigningVerificationFunction(private val textFilePath: String): Function() {
  val verified: Boolean
  private val signatureFilePath: String = "$textFilePath.sig"
  private val publicKeyFilePath: String = "$textFilePath.dsakey.pub"

  init {
    val signature = makeSignature()
    val biSignature = BigInteger(readFileContents(signatureFilePath), 16)
    val bSignatureToVerify = biSignature.toByteArray()
    verified = signature.verify(bSignatureToVerify)
  }

  private fun makeSignature(): Signature {
    val sig = Signature.getInstance("SHA1withDSA")
    val pubKey = makePublicKey()
    sig.initVerify(pubKey)
    val inputFileText = readFileContentsAsBytes(textFilePath)
    sig.update(inputFileText)
    return sig
  }
  private fun makePublicKey(): PublicKey {
    val bPub = File(publicKeyFilePath).readBytes()
    val x509EncodedKeySpec = X509EncodedKeySpec(bPub)
    val keyFactory = KeyFactory.getInstance("DSA")
    return keyFactory.generatePublic(x509EncodedKeySpec)
  }

  override fun accept(visitor: ResultManager) = visitor.visit(this)
}