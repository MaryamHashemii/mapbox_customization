package com.mapbox.mapboxsdk.module.http;

import static com.mapbox.mapboxsdk.module.http.HttpRequestUtil.toHumanReadableAscii;

import android.os.Build;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;

import com.mapbox.mapboxsdk.BuildConfig;
import com.mapbox.mapboxsdk.Mapbox;
import com.mapbox.mapboxsdk.constants.MapboxConstants;
import com.mapbox.mapboxsdk.http.HttpIdentifier;
import com.mapbox.mapboxsdk.http.HttpLogger;
import com.mapbox.mapboxsdk.http.HttpRequest;
import com.mapbox.mapboxsdk.http.HttpRequestUrl;
import com.mapbox.mapboxsdk.http.HttpResponder;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.NoRouteToHostException;
import java.net.ProtocolException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.CertificatePinner;
import okhttp3.Dispatcher;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okio.Buffer;

public class HttpRequestImpl implements HttpRequest {

  private static final String userAgentString = toHumanReadableAscii(
    String.format("%s %s (%s) Android/%s (%s)",
      HttpIdentifier.getIdentifier(),
      BuildConfig.MAPBOX_VERSION_STRING,
      BuildConfig.GIT_REVISION_SHORT,
      Build.VERSION.SDK_INT,
      Build.CPU_ABI)
  );

  private static final String sig = HttpIdentifier.getCertificateSHA1Fingerprint();
  private static final String bundle = HttpIdentifier.getPackageName();
  //optional
  private final String basicAuth = "Basic " + Base64.encodeToString("every thing you want(the secret key for use the services,your server side api should accept it and give you accebility)".getBytes(), Base64.NO_WRAP);


  @VisibleForTesting
  static final OkHttpClient DEFAULT_CLIENT = getUnsafeOkHttpClient();

  @VisibleForTesting
  static OkHttpClient client = DEFAULT_CLIENT;


  private Call call;

  @Override
  public void executeRequest(HttpResponder httpRequest, long nativePtr, @NonNull String resourceUrl,
                             @NonNull String etag, @NonNull String modified, boolean offlineUsage) {
    if (!resourceUrl.contains("access_token="))
      resourceUrl = resourceUrl + (resourceUrl.contains("?") ? "&apikey=" : "?apikey=") + Mapbox.getAccessToken();

    OkHttpCallback callback = new OkHttpCallback(httpRequest);
    try {
      HttpUrl httpUrl = HttpUrl.parse(resourceUrl);
      if (httpUrl == null) {
        HttpLogger.log(Log.ERROR, String.format("[HTTP] Unable to parse resourceUrl %s", resourceUrl));
        return;
      }

      final String host = httpUrl.host().toLowerCase(MapboxConstants.MAPBOX_LOCALE);
      resourceUrl = HttpRequestUrl.buildResourceUrl(host, resourceUrl, httpUrl.querySize(), offlineUsage);

      final Request.Builder builder = new Request.Builder()
        .url(resourceUrl)
        .tag(resourceUrl.toLowerCase(MapboxConstants.MAPBOX_LOCALE))
        .addHeader("sig", sig)
        .addHeader("bundle", bundle)
        .addHeader("User-Agent", userAgentString)
        .addHeader("Authorization", basicAuth);

      if (etag.length() > 0) {
        builder.addHeader("If-None-Match", etag);
      } else if (modified.length() > 0) {
        builder.addHeader("If-Modified-Since", modified);
      }

      final Request request = builder.build();
      call = client.newCall(request);
      call.enqueue(callback);
    } catch (Exception exception) {
      callback.handleFailure(call, exception);
    }
  }

  @Override
  public void cancelRequest() {
    // call can be null if the constructor gets aborted (e.g, under a NoRouteToHostException).
    if (call != null) {
      HttpLogger.log(Log.DEBUG, String.format("[HTTP] This request was cancelled (%s). This is expected for tiles"
        + " that were being prefetched but are no longer needed for the map to render.", call.request().url()));
      call.cancel();
    }
  }

  public static void enablePrintRequestUrlOnFailure(boolean enabled) {
    HttpLogger.logRequestUrl = enabled;
  }

  public static void enableLog(boolean enabled) {
    HttpLogger.logEnabled = enabled;
  }

  public static void setOkHttpClient(@Nullable OkHttpClient okHttpClient) {
    if (okHttpClient != null) {
      HttpRequestImpl.client = okHttpClient;
    } else {
      HttpRequestImpl.client = DEFAULT_CLIENT;
    }
  }

  private static class OkHttpCallback implements Callback {

    private HttpResponder httpRequest;

    OkHttpCallback(HttpResponder httpRequest) {
      this.httpRequest = httpRequest;
    }

    @Override
    public void onFailure(@NonNull Call call, @NonNull IOException e) {
      handleFailure(call, e);
    }

    @Override
    public void onResponse(@NonNull Call call, @NonNull Response response) {
      if (response.isSuccessful()) {
        HttpLogger.log(Log.VERBOSE, String.format("[HTTP] Request was successful (code = %s).", response.code()));
      } else {
        // We don't want to call this unsuccessful because a 304 isn't really an error
        String message = !TextUtils.isEmpty(response.message()) ? response.message() : "No additional information";
        HttpLogger.log(Log.DEBUG, String.format("[HTTP] Request with response = %s: %s", response.code(), message));
      }

      ResponseBody responseBody = response.body();
      if (responseBody == null) {
        HttpLogger.log(Log.ERROR, "[HTTP] Received empty response body");
        return;
      }

      byte[] body;
      try {
        body = responseBody.bytes();
      } catch (IOException ioException) {
        onFailure(call, ioException);
        // throw ioException;
        return;
      } finally {
        response.close();
      }

      // its because of they are some png file in your tiles and png cant decode and encode to string
      if (!response.request().url().toString().contains("apikey")
              && !response.request().url().toString().contains("sprite")
              && !response.request().url().toString().contains("fonts")) {

          String stringBody = new String(body);
          stringBody = stringBody.replace("your first section of url://", "mapbox://");
          body = stringBody.getBytes();
      }

      httpRequest.onResponse(response.code(),
        response.header("ETag"),
        response.header("Last-Modified"),
        response.header("Cache-Control"),
        response.header("Expires"),
        response.header("Retry-After"),
        response.header("x-rate-limit-reset"),
        body);
    }

    private void handleFailure(@Nullable Call call, Exception e) {
      String errorMessage = e.getMessage() != null ? e.getMessage() : "Error processing the request";
      int type = getFailureType(e);

      if (HttpLogger.logEnabled && call != null && call.request() != null) {
        String requestUrl = call.request().url().toString();
        HttpLogger.logFailure(type, errorMessage, requestUrl);
      }
      httpRequest.handleFailure(type, errorMessage);
    }

    private int getFailureType(Exception e) {
      if ((e instanceof NoRouteToHostException) || (e instanceof UnknownHostException) || (e instanceof SocketException)
        || (e instanceof ProtocolException) || (e instanceof SSLException)) {
        return CONNECTION_ERROR;
      } else if ((e instanceof InterruptedIOException)) {
        return TEMPORARY_ERROR;
      }
      return PERMANENT_ERROR;
    }
  }

  @NonNull
  private static Dispatcher getDispatcher() {
    Dispatcher dispatcher = new Dispatcher();
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
      // Matches core limit set on
      // https://github.com/mapbox/mapbox-gl-native/blob/master/platform/android/src/http_file_source.cpp#L192
      dispatcher.setMaxRequestsPerHost(20);
    } else {
      // Limiting concurrent request on Android 4.4, to limit impact of SSL handshake platform library crash
      // https://github.com/mapbox/mapbox-gl-native/issues/14910
      dispatcher.setMaxRequestsPerHost(10);
    }
    return dispatcher;
  }


  private static OkHttpClient getUnsafeOkHttpClient() {
    try {
      CertificatePinner certificatePinner = new CertificatePinner.Builder()
              .add("your domain", "your key")
              .build();

      X509TrustManager trustManager;
      SSLSocketFactory sslSocketFactory;
      try {
        trustManager = trustManagerForCertificates(trustedCertificatesInputStream());
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{trustManager}, null);
        sslSocketFactory = sslContext.getSocketFactory();
      } catch (GeneralSecurityException e) {
        throw new RuntimeException(e);
      }

      OkHttpClient.Builder builder = new OkHttpClient.Builder()
              .sslSocketFactory(sslSocketFactory, trustManager)
              .hostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String s, SSLSession sslSession) {
                  return true;
                }
              })
              .certificatePinner(certificatePinner)
              .dispatcher(getDispatcher());

      return builder.build();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

  }

  private static InputStream trustedCertificatesInputStream() {
    // PEM files for root certificates of Comodo and Entrust. These two CAs are sufficient to view
    // https://publicobject.com (Comodo) and https://squareup.com (Entrust). But they aren't
    // sufficient to connect to most HTTPS sites including https://godaddy.com and https://visa.com.
    // Typically developers will need to get a PEM file from their organization's TLS administrator.
    String comodoRsaCertificationAuthority = "-----BEGIN CERTIFICATE-----\n" +
            "MIIEADCCAuigAwIBAgICEAMwDQYJKoZIhvcNAQELBQAwgYIxCzAJBgNVBAYTAklS\n" +
            "MQ8wDQYDVQQIDAZUZWhyYW4xDzANBgNVBAcMBlRlaHJhbjEOMAwGA1UECgwFTWF0\n" +
            "aW4xEjAQBgNVBAsMCVRlY2huaWNhbDEQMA4GA1UEAwwHbXR5bi5pcjEbMBkGCSqG\n" +
            "SIb3DQEJARYMaW5mb0BtdHluLmlyMB4XDTE5MDgwNDExMTg0NVoXDTI5MDgwMTEx\n" +
            "MTg0NVowgYUxCzAJBgNVBAYTAklSMQ8wDQYDVQQIDAZUZWhyYW4xDzANBgNVBAcM\n" +
            "BlRlaHJhbjEPMA0GA1UECgwGUm91dGFhMRIwEAYDVQQLDAlUZWNobmljYWwxETAP\n" +
            "BgNVBAMMCFJvdXRhLmlyMRwwGgYJKoZIhvcNAQkBFg1pbmZvQHJvdXRhLmlyMIIB\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtc4R6mDSUmGUAkhqA2BsI11E\n" +
            "xrDI9FuSXF9Y1Tr5cg/7w1VRQKhwc/D1bVLY8VZPB0ZkRqNCwDyhLLUxEWlNs7k7\n" +
            "W+BEtDHdx+xxY1DySGzqsg1O6bCtLMh9FvTwBUnzNRdyqvQke+jx1s7eY+eUXg4A\n" +
            "I9XAekvtVBrvgYtSeoICA4M/9RP0xSnDttVFIABD6ABKZTzGOdcKeMMFH7n9mWV+\n" +
            "q6d8Zb5yt+Nqm15AjikgR6Z4mAuQ7cMgWFEeMWDM5qQKtx949SWI/tNK+ZHYAOzt\n" +
            "N8mWDJm/29dAPgrRV0Fijy61IqSul6gyeEg0p6ksasuvHlzR+f7b6DaYUGbGNwID\n" +
            "AQABo3sweTAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVy\n" +
            "YXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUPIWnGImvJ6wM5W8dA5GalqP4Le0w\n" +
            "HwYDVR0jBBgwFoAU5vbyhVIywoIXk1J0ledFSDSV6W4wDQYJKoZIhvcNAQELBQAD\n" +
            "ggEBAI6qenJOx0VrpKB9/HstUVDZh8IC6oQC9cQNV6HP+MMa5+NaCoi1VCtLeaI6\n" +
            "UhNm2PGwGZi7G5Lj1QHZcn/IV66rVxM0jitDlSGSqNJzCapaFOVj9HTh1W5XNAtl\n" +
            "eSPNVnLSS72cjkdyTc6vwwECN4Wk58dcB1M/O702SkCHKkY3RWGnt0g45+NoOQfo\n" +
            "J8cIEzy/9xw+UGa96k69jijsGAfJbg6bvGqIeV6K65NfTsaWCOzK/BuXhCLxXghh\n" +
            "imT6Gk/ba+yW2SGybJ5nmvicb3XHgl8eMAdpBMw2lMqy68A5iwiBco2oxkBlA96B\n" +
            "0GgdWgreuEOek012dmjPOfhwIRc=\n" +
            "-----END CERTIFICATE-----";
    return new Buffer()
            .writeUtf8(comodoRsaCertificationAuthority)
            .inputStream();
  }

  private static X509TrustManager trustManagerForCertificates(InputStream in)
          throws GeneralSecurityException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
    if (certificates.isEmpty()) {
      throw new IllegalArgumentException("expected non-empty set of trusted certificates");
    }

    // Put the certificates a key store.
    char[] password = "password".toCharArray(); // Any password will work.
    KeyStore keyStore = newEmptyKeyStore(password);
    int index = 0;
    for (Certificate certificate : certificates) {
      String certificateAlias = Integer.toString(index++);
      keyStore.setCertificateEntry(certificateAlias, certificate);
    }

    // Use it to build an X509 trust manager.
    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, password);
    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(keyStore);
    TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
    if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
      throw new IllegalStateException("Unexpected default trust managers:"
              + Arrays.toString(trustManagers));
    }
    return (X509TrustManager) trustManagers[0];
  }

  private static KeyStore newEmptyKeyStore(char[] password) throws GeneralSecurityException {
    try {
      KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      InputStream in = null; // By convention, 'null' creates an empty key store.
      keyStore.load(in, password);
      return keyStore;
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }
}
