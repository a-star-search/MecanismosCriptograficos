package es.uc3m.masterfintech.seguridad.function

import es.uc3m.masterfintech.seguridad.ResultManager
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.tsp.TimeStampResp
import org.bouncycastle.tsp.TimeStampRequest
import org.bouncycastle.tsp.TimeStampRequestGenerator
import org.bouncycastle.cms.CMSAlgorithm.*
import org.bouncycastle.tsp.TimeStampResponse
import sun.security.jca.GetInstance
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import kotlin.text.Charsets.UTF_8

internal class TimestampFunction(sFile: String) : Function()  {
  val encodedTimeStampToken: String
  val granted: Boolean

  init {
    val bText = readFileContentsAsBytes(sFile)
    val request = makeTimestampRequest(bText)
    request.messageImprintAlgOID
    val response = TimestapResponseFetcher.fetchTimestampResponse(request)
    val encodedToken = response.timeStampToken.encoded
    encodedTimeStampToken = encodedToken.toString(UTF_8)
    val status = response.status
    granted = status == 0
  }

  override fun accept(visitor: ResultManager) = visitor.visit(this)

  companion object {
    /**
     * Crea un Time Stamp Request RFC 3161
     */
    private fun makeTimestampRequest(byteContent: ByteArray): TimeStampRequest {
      val requestGenerator = TimeStampRequestGenerator()
      requestGenerator.setCertReq(true)
      val bDigest = digest(byteContent)
      return requestGenerator.generate(SHA256, bDigest)
    }

    private fun digest(bytes: ByteArray): ByteArray {
      val sha2 = MessageDigest.getInstance("SHA-256")!!
      return sha2.digest(bytes)!!
    }
  }
}
object TimestapResponseFetcher {
  private const val TSA_URL: String = "http://zeitstempel.dfn.de"
  private const val CHARSET = "UTF-8"
  private const val TS_QUERY_MIME_TYPE = "application/timestamp-query"
  private const val CONNECTION_TIMEOUT = 10_000

  fun fetchTimestampResponse(request: TimeStampRequest): TimeStampResponse {
    val bRequest = request.encoded!!
    val connection = makeHTTPConnection(bRequest.size)
    postRequestToHTTPConnection(connection, bRequest)
    return readResponseFromHTTPConnection(connection)
  }

  private fun makeHTTPConnection(size: Int): HttpURLConnection {
    val connection = URL(TSA_URL).openConnection() as HttpURLConnection
    connection.doOutput = true
    connection.requestMethod = "POST"
    connection.setRequestProperty("Content-Type", "$TS_QUERY_MIME_TYPE;charset=$CHARSET")
    connection.setRequestProperty("Accept-Charset", CHARSET)
    connection.setRequestProperty("Content-length", size.toString())
    connection.connectTimeout = CONNECTION_TIMEOUT
    return connection
  }

  private fun postRequestToHTTPConnection(connection: HttpURLConnection, bRequest: ByteArray) =
    connection.outputStream.use { output -> output.write(bRequest) }

  private fun readResponseFromHTTPConnection(connection: HttpURLConnection): TimeStampResponse {
    val inputStreamResponse = connection.inputStream!!
    val asn1 = ASN1InputStream(inputStreamResponse).readObject()!!
    val resp = TimeStampResp.getInstance(asn1)!!
    return TimeStampResponse(resp)
  }
}