// The Angular test environment under vitest + jsdom: zone.js patches,
// then the TestBed environment. The spec files are standard Jasmine
// syntax and vitest's expect covers the matchers they use (toBe,
// toEqual, not.toBeNull), so no matcher shim is needed.
import 'zone.js';
import 'zone.js/testing';
import { getTestBed } from '@angular/core/testing';
import {
  BrowserDynamicTestingModule,
  platformBrowserDynamicTesting,
} from '@angular/platform-browser-dynamic/testing';

getTestBed().initTestEnvironment(BrowserDynamicTestingModule, platformBrowserDynamicTesting());
