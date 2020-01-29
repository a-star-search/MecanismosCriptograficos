package es.uc3m.masterfintech.seguridad.function

import es.uc3m.masterfintech.seguridad.ResultManager
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.MessageDigest
import java.security.Security

/**
 * Utiliza SHA2 (SHA-256)
 */
internal class HashingFunction(sInputFile: String) : Function() {
  /** Como cadena de hexadecimales */
  val hash: String

  init {
    Security.addProvider(BouncyCastleProvider())
    val sha2 = MessageDigest.getInstance("SHA-256")!!
    val bContent = readFileContentsAsBytes(sInputFile)
    val bDigest = sha2.digest(bContent)!!
    hash = bytesToHexString(bDigest)
  }

  override fun accept(visitor: ResultManager) = visitor.visit(this)
}