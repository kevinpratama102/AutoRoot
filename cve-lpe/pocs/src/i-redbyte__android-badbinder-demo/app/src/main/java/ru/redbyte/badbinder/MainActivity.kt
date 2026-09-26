package ru.redbyte.badbinder

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import ru.redbyte.badbinder.ui.theme.BadBinderTheme

class MainActivity : ComponentActivity() {

    private val viewModel: ExploitViewModel by viewModels()

    init {
        System.loadLibrary("cve-2019-2215")
    }

    external fun runNativeExploit(): String
    external fun setNativeLogger(logger: NativeLogger)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setNativeLogger(viewModel)

        setContent {
            BadBinderTheme {
                ExploitScreen(
                    viewModel = viewModel,
                    onStartClick = { startExploit() }
                )
            }
        }
    }

    private fun startExploit() {
        lifecycleScope.launch(Dispatchers.IO) {
            viewModel.onStart()
            val result = runNativeExploit()
            withContext(Dispatchers.Main) {
                viewModel.onFinished(result)
            }
        }
    }
}
