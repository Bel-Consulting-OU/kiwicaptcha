// Karma configuration for the Angular widget's spec suite. The browser
// is the Playwright-managed headless Chromium (there is no system Chrome
// in this environment), pointed at via CHROME_BIN; the no-sandbox
// launcher is required because the runner is itself not sandboxed.
// Plugin auto-discovery stays enabled: it loads karma-jasmine,
// karma-chrome-launcher and the Angular build plugin the builder
// injects, so no explicit plugins array is set here.
module.exports = function (config) {
  config.set({
    basePath: '',
    frameworks: ['jasmine'],
    plugins: [
      require('karma-jasmine'),
      require('karma-chrome-launcher'),
      require('@angular-devkit/build-angular/plugins/karma'),
    ],
    logLevel: config.LOG_DEBUG,
    reporters: ['progress'],
    browsers: ['ChromeHeadlessNoSandbox'],
    customLaunchers: {
      ChromeHeadlessNoSandbox: {
        base: 'ChromeHeadless',
        flags: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
      },
    },
    restartOnFileChange: false,
    singleRun: true,
  });
};
