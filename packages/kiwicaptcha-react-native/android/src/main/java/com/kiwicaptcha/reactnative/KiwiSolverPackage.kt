package com.kiwicaptcha.reactnative

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager

/**
 * Registers the KiwiCaptchaSolver native module with React Native.
 *
 * A classic [ReactPackage] is deliberate: it works unchanged on the old
 * architecture and, from RN 0.74 on, through the legacy-module interop
 * layer of the New Architecture, so the JS lookup
 * (`TurboModuleRegistry` / `NativeModules.KiwiCaptchaSolver`) finds it
 * in every supported setup.
 *
 * React Native autolinking (the community CLI and the RN 0.75+ core
 * autolinking) discovers this package by scanning the library's
 * `android/` sources for a [ReactPackage] subclass — no
 * react-native.config.js and no manual MainApplication registration
 * are needed.
 */
class KiwiSolverPackage : ReactPackage {
    override fun createNativeModules(
        reactContext: ReactApplicationContext,
    ): List<NativeModule> = listOf(KiwiCaptchaSolverModule(reactContext))

    override fun createViewManagers(
        reactContext: ReactApplicationContext,
    ): List<ViewManager<*, *>> = emptyList()
}
