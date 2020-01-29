package es.uc3m.masterfintech.seguridad.function

import es.uc3m.masterfintech.seguridad.Mode.*
import es.uc3m.masterfintech.seguridad.ProgramOptions
import es.uc3m.masterfintech.seguridad.ResultManager
import java.io.File
import javax.xml.bind.DatatypeConverter
import javax.xml.bind.DatatypeConverter.parseHexBinary
import kotlin.text.Charsets.UTF_8

/**
 * Cada tipo de funcion que hereda de esta clase se instancia y crea su estado con los resultados que le son propios
 * (booleano, String, etc).
 *
 * Al ser heterogeneos no hay una interfaz comun para obtener esos resultados; aunque en la documentacion de esta
 * clase, a continuacion, se definen ciertos criterios comunes sobre los resultados a generar.
 *
 * Se utiliza el patron visitor (o double dispatch) para desacoplar el estado del objeto de la gestion de ese estado
 * (p.e. presentacion por pantalla, persistencia, etc)
 *
 * En cada clase que herede de esta se permite asumir que la entrada y salida para cualquier funcion (p.e. contenido
 * de ficheros de entrada) es de tamaño suficientemente pequeño para almacenarla en un objeto de tipo "String".
 *
 * Finalmente se asume que los ficheros de texto de entrada tienen siempre una codificacion UTF-8
 *
 * Asimismo cualquier fichero de salida generado tambien tendrá codificacion UTF-8
 *
 * De forma arbitraria y para homogeneizar la salida de las funciones, se decide que resumenes y cifrados deben ser
 * expresados como cadenas de hexadecimales.
 */
internal abstract class Function {
  /**
   * Devuelve el contenido de un fichero UTF-8 como cadena de caracteres
   * Asume fichero existe, es correcto, tamaño no es excesivo, etc (no hay control de errores)
   */
  protected fun readFileContents(sInputFile: String): String =
    File(sInputFile).readText(UTF_8)

  protected fun readFileContentsAsBytes(sInputFile: String): ByteArray =
    readFileContents(sInputFile).toByteArray(UTF_8)

  /**
   * Caracteres hexadecimales a array de bytes
   */
  protected fun hexStringToBytes(s: String): ByteArray = parseHexBinary(s)
  protected fun bytesToHexString(byteArray: ByteArray): String = DatatypeConverter.printHexBinary(byteArray)

  abstract fun accept(visitor: ResultManager)

  companion object {
    /** Factory method */
    fun makeFunction(options: ProgramOptions): Function =
      when(options.mode) {
        SYMMETRIC_CIPHERING.code -> makeSymmetricCipheringFunction(options)
        SYMMETRIC_DECIPHERING.code -> makeSymmetricDecipheringFunction(options)
        HASHING.code -> makeHashingFunction(options)
        HASH_VERIFICATION.code -> makeHashVerificationFunction(options)
        ASYMMETRIC_KEY_GENERATION.code -> makeAsymmetricKeyGenerationFunction()
        ASYMMETRIC_CIPHERING.code -> makeAsymmetricCipheringFunction(options)
        ASYMMETRIC_DECIPHERING.code -> makeAsymmetricDecipheringFunction(options)
        TIMESTAMPING.code -> makeTimestampingFunction(options)
        TIMESTAMPING_VERIFICATION.code -> makeTimestampingVerificationFunction(options)
        SIGNING_VERIFICATION.code -> makeSigningVerificationFunction(options)
        SIGNING.code -> makeSigningFunction(options)
        else -> throw UnknownFunctionException("")
      }

    private fun makeTimestampingVerificationFunction(options: ProgramOptions): Function {
      TODO("not implemented")
    }

    private fun makeTimestampingFunction(options: ProgramOptions): Function {
      val sInputFile = options.input!!
      return TimestampFunction(sInputFile)
    }

    private fun makeAsymmetricDecipheringFunction(options: ProgramOptions): Function {
      val sInputFile = options.input!!
      val sAdditional  = options.additional!!
      return AsymmetricDecipheringFunction(sInputFile, sAdditional)
    }

    private fun makeAsymmetricCipheringFunction(options: ProgramOptions): Function {
      val sInputFile = options.input!!
      val pass  = options.pass!!
      return AsymmetricCipheringFunction(sInputFile, pass)
    }

    private fun makeAsymmetricKeyGenerationFunction(): Function =
      AsymmetricKeysGenerationFunction()

    private fun makeHashingFunction(options: ProgramOptions): Function {
      val sInputFile = options.input!!
      return HashingFunction(sInputFile)
    }

    private fun makeSymmetricDecipheringFunction(options: ProgramOptions): Function {
      val sInputFile = options.input!!
      val pass = options.pass!!
      return SymmetricDecipheringFunction(sInputFile, pass)
    }

    private fun makeSymmetricCipheringFunction(options: ProgramOptions): Function {
      val sInputFile = options.input!!
      val pass = options.pass!!
      return SymmetricCipheringFunction(sInputFile, pass)
    }

    private fun makeHashVerificationFunction(options: ProgramOptions): Function {
      val sInputFile = options.input!!
      val sHashFile = options.additional!!
      return HashVerificationFunction(sInputFile, sHashFile)
    }

    private fun makeSigningVerificationFunction(options: ProgramOptions): Function =
      SigningVerificationFunction(options.input)

    private fun makeSigningFunction(options: ProgramOptions): Function =
      SigningFunction(options.input)
  }
}