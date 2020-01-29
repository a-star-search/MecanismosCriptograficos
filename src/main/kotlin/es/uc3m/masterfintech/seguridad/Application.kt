package es.uc3m.masterfintech.seguridad

import com.google.devtools.common.options.OptionsParser
import java.util.Collections.emptyMap
import es.uc3m.masterfintech.seguridad.function.Function

class Application {
  companion object {
    @JvmStatic
    fun main(args: Array<String>) {
      val parser = getParser(args)
      val options = parser.getOptions(ProgramOptions::class.java)!!
      val correctOptions = OptionValidator.validateOptions(options)
      if (correctOptions)
        executeFunction(options)
      else
        printUsage(parser)
    }

    private fun executeFunction(options: ProgramOptions) {
      val function = Function.makeFunction(options)
      val resultManager = makeResultManager(options)
      function.accept(resultManager)
    }

    private fun makeResultManager(options: ProgramOptions) = ResultManagerImpl(options.output, options.write)

    private fun getParser(args: Array<String>): OptionsParser {
      val parser = OptionsParser.newOptionsParser(ProgramOptions::class.java)!!
      parser.parseAndExitUponError(args)
      return parser
    }

    private fun printUsage(parser: OptionsParser) {
      println("Usage: java -jar CriptoFinanciera.jar -m [cs | ds | h | vh | gca | ca | da | s | vs | ts | vts]\n" +
              "  [-p contraseña] -i fichero [-a adicional] [-o salida] [-v]")
      println(parser.describeOptions( emptyMap(), OptionsParser.HelpVerbosity.LONG) )
    }
  }
}
