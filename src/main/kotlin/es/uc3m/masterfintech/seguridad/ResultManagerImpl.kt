package es.uc3m.masterfintech.seguridad

import es.uc3m.masterfintech.seguridad.function.*
import java.io.File
import javax.xml.bind.DatatypeConverter
import javax.xml.bind.DatatypeConverter.printHexBinary

internal class ResultManagerImpl(private val sOutputFile: String?, private val persist: Boolean) : ResultManager {

  override fun visit(f: HashVerificationFunction) =
    writeVerificationResult(f.isVerified)

  override fun visit(f: SymmetricCipheringFunction) =
    writeResult(f.cipheredText)

  override fun visit(f: SymmetricDecipheringFunction) =
    writeResult(f.clearText)

  override fun visit(f: AsymmetricCipheringFunction) =
    writeResult(f.rsaCipheredPassword)

  override fun visit(f: AsymmetricDecipheringFunction) =
    writeResult(f.clearText)

  override fun visit(f: HashingFunction) =
    writeResult(f.hash)

  override fun visit(f: TimestampFunction) =
    writeResult(f.encodedTimeStampToken)

  override fun visit(f: TimestampVerificationFunction) = writeVerificationResult(f.verified)

  override fun visit(f: SigningFunction) {
    val sSignature = f.signature.toString(16)
    if(!persist){
      println("Signature: $sSignature")
      println("Public key: " + printHexBinary(f.bPublic))
      println("Private key: " + printHexBinary(f.bPrivate))
    } else {
      File("${f.sInputFile}.sig").writeText(sSignature)
      File("${f.sInputFile}.dsakey.pub").writeBytes(f.bPublic)
      File("${f.sInputFile}.dsakey.pri").writeBytes(f.bPrivate)
    }
  }

  override fun visit(f: SigningVerificationFunction) =
    writeVerificationResult(f.verified)

  override fun visit(f: AsymmetricKeysGenerationFunction) {
    if(sOutputFile.isNullOrEmpty()){
      println(f.sPublicKey)
      println(f.sPrivateKey)
      return
    }
    val pubKeyFile = File("$sOutputFile.pub")
    pubKeyFile.writeText(f.sPublicKey)

    val priKeyFile = File("$sOutputFile.pri")
    priKeyFile.writeText(f.sPrivateKey)
  }

  private fun writeResult(result: String) {
    if(sOutputFile.isNullOrEmpty()){
      println(result)
      return
    }
    val f = File(sOutputFile)
    f.writeText(result)
  }

  private fun writeVerificationResult(result: Boolean)   =
    writeResult( if(result) "Verificado correctamente" else "No pudo ser verificada")
}