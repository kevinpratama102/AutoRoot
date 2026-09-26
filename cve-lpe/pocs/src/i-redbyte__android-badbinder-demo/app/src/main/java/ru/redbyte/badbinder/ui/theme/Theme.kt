package ru.redbyte.badbinder.ui.theme

import android.app.Activity
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

// Матрица ✳️
private val MatrixGreen = Color(0xFF00FF41)
private val MatrixGreenSoft = Color(0xFF5CFF95)

private val MatrixBg = Color(0xFF020403)            // общий фон
private val MatrixSurface = Color(0xFF050807)       // карточки
private val MatrixSurfaceVariant = Color(0xFF0A1410)

private val DarkColorScheme = darkColorScheme(
    primary = MatrixGreen,
    onPrimary = Color.Black,
    secondary = MatrixGreenSoft,
    onSecondary = Color.Black,
    tertiary = Color(0xFFFF5555),                  // красный только для ошибок
    onTertiary = Color.Black,

    background = MatrixBg,
    onBackground = Color(0xFFE4F7E9),

    surface = MatrixSurface,
    onSurface = Color(0xFFE4F7E9),

    surfaceVariant = MatrixSurfaceVariant,
    onSurfaceVariant = Color(0xFFB0C3B8),

    outline = MatrixGreenSoft.copy(alpha = 0.5f)
)

@Composable
fun BadBinderTheme(
    content: @Composable () -> Unit
) {
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = MatrixBg.toArgb()
            WindowCompat.getInsetsController(window, view)
                .isAppearanceLightStatusBars = false
        }
    }

    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography = Typography(),
        content = content
    )
}
