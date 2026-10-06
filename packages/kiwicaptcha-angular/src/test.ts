// Karma entry point for the Angular widget's spec suite. The Angular
// library test setup needs an explicit TestBed environment plus a
// context-glob over the spec files. require.context must be a direct
// static call for the webpack-based karma builder to lower it; the
// declared type keeps TypeScript strict mode happy without a cast
// wrapper.
import 'zone.js';
import 'zone.js/testing';
import { getTestBed } from '@angular/core/testing';
import {
  BrowserDynamicTestingModule,
  platformBrowserDynamicTesting,
} from '@angular/platform-browser-dynamic/testing';

declare const require: {
  context(dir: string, deep: boolean, re: RegExp): { keys(): string[]; (key: string): unknown };
};

getTestBed().initTestEnvironment(BrowserDynamicTestingModule, platformBrowserDynamicTesting());

const context = require.context('./', true, /\.spec\.ts$/);
context.keys().forEach((key) => context(key));
