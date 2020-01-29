package es.uc3m.masterfintech.seguridad.function

import es.uc3m.masterfintech.seguridad.ResultManager

internal class HashVerificationFunction(sInputFile: String, sHashFile: String) : Function() {
  val isVerified: Boolean

  init {
    val expectedHash = readFileContents(sHashFile)
    val f = HashingFunction(sInputFile)
    val actualHash = f.hash
    isVerified = actualHash == expectedHash
  }

  override fun accept(visitor: ResultManager) = visitor.visit(this)
}