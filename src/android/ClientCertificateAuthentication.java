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
            InputStream astream = cordova.getActivity().getApplicationContext().getAssets().open(p12path);
            keystore.load(astream, p12password.toCharArray());
            astream.close();
            Enumeration e = keystore.aliases();
            if (e.hasMoreElements()) {
                String ealias = (String) e.nextElement();
                PrivateKey key = (PrivateKey) keystore.getKey(ealias, p12password.toCharArray());
                java.security.cert.Certificate[]  chain = keystore.getCertificateChain(ealias);
                X509Certificate[] certs = Arrays.copyOf(chain, chain.length, X509Certificate[].class);
                request.proceed(key,certs);
            } else
            {
                request.ignore();
            }

        } catch (Exception ex)
        {
            request.ignore();
        }
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
