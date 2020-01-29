Programa de línea de comandos que demuestra el funcionamiento de distintas funciones criptográficas.

Empaquetado JAR
--
Debido a problemas con la libreria BouncyCastle y la construccion del Jar con dependencias con maven, he
decidido no utilizar maven para construir el Jar y en su lugar utilizar Intellij IDEA para generarlo.

Es decir el fichero pom genera errores al intentar construir el jar con dependencias.

Es posible que con el jar generado por IDEA salte una excepcion con el siguiente mensaje
"Exception in thread "main" java.lang.SecurityException: Invalid signature file digest for Manifest main attributes"
Esto se puede resolver ejecutando en windows:
zip -d MecanismosCriptograficos.jar "META-INF/*.SF" "META-INF/*.RSA" "META-INF/*SF"

Ejecucion
--
Este programa asume que todos los ficheros a procesar no son excesivamente grandes, ya que internamente se utilizan
cadenas de caracteres para todas las operaciones.
