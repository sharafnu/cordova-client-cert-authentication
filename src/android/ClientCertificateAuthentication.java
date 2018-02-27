package de.jstd.cordova.plugin;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.ICordovaClientCertRequest;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.concurrent.ExecutorService;


@TargetApi(Build.VERSION_CODES.LOLLIPOP)
public class ClientCertificateAuthentication extends CordovaPlugin {


    public static final String SP_KEY_ALIAS = "SP_KEY_ALIAS";
    public static final String TAG = "client-cert-auth";

    X509Certificate[] mCertificates;
    PrivateKey mPrivateKey;
    String mAlias;


    @Override
    public Boolean shouldAllowBridgeAccess(String url) {
        return super.shouldAllowBridgeAccess(url);
    }


    @TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
    @Override
    public boolean onReceivedClientCertRequest(CordovaWebView view, ICordovaClientCertRequest request) {

        try {
            KeyStore keystore = KeyStore.getInstance("PKCS12");

            InputStream astream = cordova.getActivity().getApplicationContext().getAssets().open("www/TESTAPI-FEB.p12");
            keystore.load(astream, "password".toCharArray());
            astream.close();
            Enumeration e = keystore.aliases();
            if (e.hasMoreElements()) {
                byte[] decoded = Base64.decode("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCPR127G+KL+rO+\n" +
                        "DINYSIyQp1G2zKgGT6p89c00n9dWEOiOolxRCYSjQ4c6eWBdhjFSOcxqJafiTTK1\n" +
                        "bmGkA3VdfPKS/jFWEGOFHko+fucJpq26CE7rvX/iGo/oXfroKXVEWlCy4vCWjVf0\n" +
                        "UT5DfJUJBHAxmT+HeC2ixJoxmbwM9TmXglxIMSTqQqk8Y9KiVmBriml1UoZt0hW8\n" +
                        "oH4waWgPv2pkzsiUJm8LdPZ70vjXcWQWSXA2vUdkouzQUni1X1a6nbeUlE9A4zt/\n" +
                        "gODtqQ22NUMTTxkHNZ52/a9wCT+8aoCVAQ4JzB2f8TPMZn9ZGJlFYsc1YlmZKuPv\n" +
                        "62eGDoJRAgMBAAECggEABOPr0TR6EqrJioOxEnj0ckYBuh5pYEDFGguGN+T6Q7Xj\n" +
                        "SCYGxl3PrQZjpdVpenu3cH3oShmzrZvSrqJgOwnCrmCSw31hV/WKfgtK/6/TaS8L\n" +
                        "GDHLJszyodgkAAuAIj8zAVSfU0G/cjYMEdrZiBJnIFYKUckQI+qwTRFOjYGYq20A\n" +
                        "tzzD0IllEGVk00CKlvpGVv3m9ZvCgegOySS9g5szJabUtyPtEiuc1y3yv2rU/AYb\n" +
                        "zjBJ7PgtLxl56LpgKaJHUdSDEsIIP7GI+h4SzS+OXrd2PuVoyZAtj8a0rjyGDizU\n" +
                        "hfero1KA9DWqSrpQlVNQTGnqAaoON5+x3sZ9+XVMAQKBgQDHAVLYSIpwtEC+Yffo\n" +
                        "M+zA2u/RxYNBsFuUaekvyVL2vuU93fntDonqNUsvWNTPnTNIVmYMASlqENKcHCnD\n" +
                        "+vYtjoUb56D9tNMP1S6leoAbVudCwCpPYryLxpGmdO5pVUbtZTLFF9Zyf9jyTV+q\n" +
                        "oxZCKcmMYMyhne40kY9lAxViAQKBgQC4UEpRiWBk8+81eB0qtFquMporP6DKWbAM\n" +
                        "mCrHJVQg2V+wjpj6d+ZdD94qmuh8IY3/Gqzx/eq2BtheTKOiAD5VwCaGNvz1tR3X\n" +
                        "cdYuxiKEYz5iP8GOjIPRC7CxZNQ4TW4zARcEaFKm/scK2LJc/C0K9hfmvzvSMo2G\n" +
                        "7gwKh0qAUQKBgQCuPstyEvocusdhq1gsmaJ4LnsDmsRVtPxK0/1YWRfqcrU4WW8n\n" +
                        "EK7TQnylZUtYydUIRpYtdqrzcu1lwQcU0V3R/9Mu3r5IxpZza37fZ4ZZ6dqtyKKD\n" +
                        "Rfm/DUukiwfhdMiYvh4ZEskzEhw79GGKgCfSINKXtn4WGLlkj/sVQADuAQKBgEVU\n" +
                        "jmAVWNkgmP537CDALswP5MYX7RewnPRf2NeIRxkEK2ZyfUDaESE4cs1776+hv5QS\n" +
                        "KLPuW3eVI5Z1Jaguh0QiP1uFG6ohMtRz0alOhnVeD31NljVUzdC4oQJZdyqmlalB\n" +
                        "47KYu15tv9looc8wXJEe+OanUI1Ezs/Og2ECexfBAoGAFSp4tDRxu+SF3rFXWiYc\n" +
                        "1MuPkMkVhuwBA0yzogUP8rFcfXJRbiuhoMYNurhcqytXyaC99aW6i6eEvhnPY0qw\n" +
                        "E3tZwK3twGcHqjFqW5L8lqUwWXw22oPGpsu9ZzF1e5LTq7qlZDrD8CzdOkTRe7Um\n" +
                        "SnibZp0OC5k9G3T9NwmW+e8=",1);

                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PrivateKey mkey = kf.generatePrivate(spec);

                String ealias = (String) e.nextElement();
                PrivateKey key = (PrivateKey) keystore.getKey(ealias, "password".toCharArray());
                java.security.cert.Certificate[]  chain = keystore.getCertificateChain(ealias);
                //X509Certificate[] certs = Arrays.copyOf(chain, chain.length, X509Certificate[].class);
                X509Certificate[] certs = new X509Certificate[]{(X509Certificate)keystore.getCertificate(ealias)};
                request.proceed(mkey,certs);
            } else
            {
                request.ignore();
            }

        } catch (Exception ex)
        {
            request.ignore();
        }

//        if (mCertificates == null || mPrivateKey == null) {
//            loadKeys(request);
//        } else {
//            proceedRequers(request);
//        }
        return true;
    }

    private void loadKeys(ICordovaClientCertRequest request) {
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(cordova.getActivity());
        final KeyChainAliasCallback callback = new AliasCallback(cordova.getActivity(), request);
        final String alias = sp.getString(SP_KEY_ALIAS, null);

        if (alias == null) {
            KeyChain.choosePrivateKeyAlias(cordova.getActivity(), callback, new String[]{"RSA"}, null, request.getHost(), request.getPort(), null);
        } else {
            ExecutorService threadPool = cordova.getThreadPool();
            threadPool.submit(new Runnable() {
                @Override
                public void run() {
                    callback.alias(alias);
                }
            });
        }
    }


    static class AliasCallback implements KeyChainAliasCallback {


        private final SharedPreferences mPreferences;
        private final ICordovaClientCertRequest mRequest;
        private final Context mContext;

        public AliasCallback(Context context, ICordovaClientCertRequest request) {
            mRequest = request;
            mContext = context;
            mPreferences = PreferenceManager.getDefaultSharedPreferences(mContext);
        }

        @Override
        public void alias(String alias) {
            try {
                if (alias != null) {
                    SharedPreferences.Editor edt = mPreferences.edit();
                    edt.putString(SP_KEY_ALIAS, alias);
                    edt.apply();
                    PrivateKey pk = KeyChain.getPrivateKey(mContext, alias);
                    X509Certificate[] cert = KeyChain.getCertificateChain(mContext, alias);
                    mRequest.proceed(pk, cert);
                } else {
                    mRequest.proceed(null, null);
                }
            } catch (KeyChainException e) {
                String errorText = "Failed to load certificates";
                Toast.makeText(mContext, errorText, Toast.LENGTH_SHORT).show();
                Log.e(TAG, errorText, e);
            } catch (InterruptedException e) {
                String errorText = "InterruptedException while loading certificates";
                Toast.makeText(mContext, errorText, Toast.LENGTH_SHORT).show();
                Log.e(TAG, errorText, e);
            }
        }
    }

    ;


    public void proceedRequers(ICordovaClientCertRequest request) {
        request.proceed(mPrivateKey, mCertificates);
    }
}
