package net.evolution515.taskerwgtunnel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.text.TextUtils
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat


var TAG: String =  "TaskerWgTunnel";

// am broadcast -a  com.wireguard.android.action.SET_TUNNEL_UP -n 'net.evolution515.taskerwgtunnel/.MainActivity$IntentReceiver' --es tunnel Asgard

class MainActivity : AppCompatActivity()  {

    lateinit var log_view: TextView
    lateinit var btnRequestPermission: Button
    lateinit var receiver: BroadcastReceiver
    var permRuntimePermission: String = "com.wireguard.android.permission.CONTROL_TUNNELS";

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        log_view = findViewById(R.id.log_view) as TextView;
        btnRequestPermission =  findViewById(R.id.btn_request_permission) as Button;

        val that = this
        btnRequestPermission.setOnClickListener(object : View.OnClickListener {
            override fun onClick(view: View?) {
                ActivityCompat.requestPermissions(that, arrayOf(permRuntimePermission), 2)
                updateView()
            }
        })
        updateView()

        receiver  = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                Toast.makeText(applicationContext, "received", Toast.LENGTH_SHORT)
            }
        }
    }

    private fun updateView() {
        if (ContextCompat.checkSelfPermission(this, permRuntimePermission) == PackageManager.PERMISSION_GRANTED) {
            btnRequestPermission.setEnabled(false);
            log_view.setText("Permissions were granted")
        } else {
            btnRequestPermission.setEnabled(true);
            log_view.setText("Please setup permissions!")
        }
    }

    class IntentReceiver : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent == null) return
            Log.i(TAG, "Received intent")
            /*try {
                Log.d(TAG, Gson().toJson(intent))
            }
            catch (e: Exception)  {
                // do nothing
            }*/
            val action = intent.action ?: return
            Log.i("TaskerWgTunnel", "action=$action")
            val shareIntent: Intent
            shareIntent = when (action) {
                "com.wireguard.android.action.SET_TUNNEL_UP" -> Intent("com.wireguard.android.action.SET_TUNNEL_UP")
                "com.wireguard.android.action.SET_TUNNEL_DOWN" -> Intent("com.wireguard.android.action.SET_TUNNEL_DOWN")
                else -> return
            }
            val tunnelName = intent.getStringExtra("tunnel") ?: return
            val secret = intent.getStringExtra("secret") ?: ""

            // TODO Add check for secret in app
            // if (secret != "") {
            // return
            // }
            // Toast.makeText(context, "Broadcast Received $action $tunnelName", Toast.LENGTH_SHORT).show();
            val packageName: String = "com.wireguard.android";
            shareIntent.setPackage(packageName)
            shareIntent.putExtra("tunnel", tunnelName)
            context.sendBroadcast(shareIntent)
            Log.i(TAG, "Intent Received $action $tunnelName")
        }
    }

    fun blup(Context: ctx) {
        // String encrypted = KeyStoreHelper.encrypt(KEYSTORE_KEY_ALIAS, "Hello World");
        // String decrypted = KeyStoreHelper.decrypt(KEYSTORE_KEY_ALIAS, encrypted);

        try {
            //This will only create a certificate once as it checks
            //internally whether a certificate with the given name
            //already exists.
            KeyStoreHelper.createKeys(context, KEYSTORE_PASSWORD.name());
        } catch (e: Exception) {
            //Probably will never happen.
            throw RuntimeException(e);
        }
        val pass: String = KeyStoreHelper.getSigningKey(KEYSTORE_PASSWORD.name());
        if (pass == null) {
            //This is a device less than JBMR2 or something went wrong.
            //I recommend eitehr not supporting it or fetching device hardware ID as shown below.
            //do note this is barely better than obfuscation.
            //Compromised security but may prove to be better than nothing
            pass = getDeviceSerialNumber(context)
            //bitshift everything by some pre-determined amount for added seurity
            pass = bitshiftEntireString(pass);
        }
        SharedPreferences securePref = SecurePreferences(context, pass, "monkey");
    }

    fun isIntentAvailable(ctx: Context, intent: Intent): Boolean {
        val mgr: PackageManager = ctx.getPackageManager()
        val list = mgr.queryIntentActivities(
            intent,
            PackageManager.MATCH_DEFAULT_ONLY
        )
        return list.size > 0
    }


    /**
     * Bitshift the entire string to obfuscate it further
     * and make it harder to guess the password.
     */
    fun bitshiftEntireString(str: String?): String? {
        val msg = StringBuilder(str!!)
        val userKey = 6
        for (i in 0 until msg.length) {
            msg.setCharAt(i, (msg[i].toInt() + userKey).toChar())
        }
        return msg.toString()
    }

    /**
     * Gets the hardware serial number of this device.
     *
     * @return serial number or Settings.Secure.ANDROID_ID if not available.
     * Credit: SecurePreferences for Android
     */
    private fun getDeviceSerialNumber(context: Context): String? {
        // We're using the Reflection API because Build.SERIAL is only available
        // since API Level 9 (Gingerbread, Android 2.3).
        return try {
            val deviceSerial = Build::class.java.getField("SERIAL")[null] as String
            if (TextUtils.isEmpty(deviceSerial)) {
                Settings.Secure.getString(
                    context.contentResolver,
                    Settings.Secure.ANDROID_ID
                )
            } else {
                deviceSerial
            }
        } catch (ignored: Exception) {
            // Fall back  to Android_ID
            Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ANDROID_ID
            )
        }
    }
}
