package es.uc3m.masterfintech.seguridad.function

import es.uc3m.masterfintech.seguridad.ResultManager

internal class TimestampVerificationFunction: Function() {
  val verified: Boolean = true
  override fun accept(visitor: ResultManager) = visitor.visit(this)
}