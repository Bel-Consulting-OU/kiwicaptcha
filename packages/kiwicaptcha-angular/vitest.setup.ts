// The Angular test environment under vitest + jsdom: zone.js patches,
// then the TestBed environment. The specs are standard Jasmine syntax
// and vitest's expect covers their matchers (toBe, toEqual,
// not.toBeNull). Known environment limit, reproduced with a minimal
// probe component: Angular's required view-query signals never resolve
// under the jsdom transform chain in this container, so the suite is
// expected to pass in an Angular CI image with a system Chrome (see the
// README for the precise status).
import 'zone.js';
import 'zone.js/testing';
import { getTestBed } from '@angular/core/testing';
import {
  BrowserDynamicTestingModule,
  platformBrowserDynamicTesting,
} from '@angular/platform-browser-dynamic/testing';

getTestBed().initTestEnvironment(BrowserDynamicTestingModule, platformBrowserDynamicTesting());
