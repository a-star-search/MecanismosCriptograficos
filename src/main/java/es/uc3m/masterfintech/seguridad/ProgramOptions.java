package es.uc3m.masterfintech.seguridad;

import com.google.devtools.common.options.Option;
import com.google.devtools.common.options.OptionsBase;

/**
 * No puede ser una clase Kotlin
 * La libreria google-options funciona solo con una clase Java para definir las opciones ya que utiliza "reflection"
 * para obtener los atributos de la clase
 */
public class ProgramOptions extends OptionsBase {

        @Option(
                name = "mode",
                abbrev = 'm',
                help = "Modo de funcionamiento.",
                category = "startup",
                defaultValue = ""
        )
        public String mode;

        @Option(
                name = "pass",
                abbrev = 'p',
                help = "Contraseña.",
                category = "startup",
                defaultValue = ""
        )
        public String pass;

        @Option(
                name = "input",
                abbrev = 'i',
                help = "Fichero.",
                category = "startup",
                defaultValue = ""
        )
        public String input;

        @Option(
                name = "additional",
                abbrev = 'a',
                help = "Fichero adicional necesario para ciertas operaciones.",
                category = "startup",
                defaultValue = ""
        )
        public String additional;

        @Option(
                name = "output",
                abbrev = 'o',
                help = "Fichero de salida.",
                category = "startup",
                defaultValue = ""
        )
        public String output;

        @Option(
                name = "write",
                abbrev = 'w',
                help = "Escribe la salida en ficheros basado en el nombre del fichero de entrada.",
                category = "startup",
                defaultValue = "false"
        )
        public boolean write;
}
