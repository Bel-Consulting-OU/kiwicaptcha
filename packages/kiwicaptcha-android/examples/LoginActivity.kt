/*
 * Example: the KiwiCaptcha View in a login Activity and the headless
 * solver on a worker dispatcher.
 */
package com.kiwicaptcha.example

import android.os.Bundle
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.kiwicaptcha.KiwiCaptchaView
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class LoginActivity : AppCompatActivity() {
    private lateinit var captcha: KiwiCaptchaView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)
        captcha = findViewById(R.id.captcha)
        captcha.endpoint = "https://api.example.com/api/kcaptcha/challenge"
        captcha.scope = "login"
        captcha.onVerify = { token -> findViewById<EditText>(R.id.kiwi_token).setText(token) }
        captcha.onError = { message -> Toast.makeText(this, message, Toast.LENGTH_SHORT).show() }
        captcha.start()
    }

    /** Headless solve on a worker dispatcher (no widget). */
    private fun headlessSolve() {
        CoroutineScope(Dispatchers.Default).launch {
            val client = KiwiClient("https://api.example.com/api/kcaptcha/challenge")
            val challenge = withContext(Dispatchers.IO) { client.fetchChallenge("login") }
            val solution = KiwiSolver.solve(challenge)
            val token = KiwiToken.encode(challenge, solution)
            withContext(Dispatchers.Main) { use(token) }
        }
    }

    private fun use(token: String): Unit = Unit
}
