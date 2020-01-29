package es.uc3m.masterfintech.seguridad.function

import es.uc3m.masterfintech.seguridad.ResultManager
import java.io.File
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.RSAPrivateKeySpec
import java.security.spec.RSAPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.Cipher.*
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.PSource.*
import javax.xml.bind.DatatypeConverter
import kotlin.text.Charsets.UTF_8


internal class AsymmetricDecipheringFunction(rsaCipheredSymmKeyFile: String, rsaPrivateKeyFile: String) : Function() {
  val clearText: String

  init {
    //solo deberia usarse para ficheros pequeños
    val lines = Files.readAllLines(Paths.get(rsaPrivateKeyFile))!!
    val sModulus = lines[2]!! //3rd line
    val sExponent = lines[4]!! //5th line
    val modulus = BigInteger(sModulus)
    val exponent = BigInteger(sExponent)
    val keyFactory = KeyFactory.getInstance(AsymmetricCipheringFunction.ALGORITHM)!!
    val privateKeySpec = RSAPrivateKeySpec(modulus, exponent)
    val key = keyFactory.generatePrivate(privateKeySpec) as RSAPrivateKey

    val oaepFromInit = getInstance("RSA/ECB/OAEPPadding")!!
    val oaepParams = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec("SHA-1"), PSpecified.DEFAULT)
    oaepFromInit.init(DECRYPT_MODE, key, oaepParams)
    val rsaCipheredSymmKey = readFileContents(rsaCipheredSymmKeyFile)
    val cipheredBytes = DatatypeConverter.parseHexBinary(rsaCipheredSymmKey)!!
    val pt = oaepFromInit.doFinal(cipheredBytes)!!
    clearText = String(pt, UTF_8)
  }

  override fun accept(visitor: ResultManager) = visitor.visit(this)
}
