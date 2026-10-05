import {
  AfterViewInit,
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  ElementRef,
  NgZone,
  inject,
  input,
  output,
  signal,
  viewChild,
} from "@angular/core";
import type {
  KiwiErrorDetail,
  KiwiRenderOptions,
  KiwiRetryDetail,
  KiwiVerifiedDetail,
  KiwiWidgetHandle,
} from "@kiwicaptcha/client-core";
import { KiwiCaptchaService, type KiwiLoadOptions } from "./kiwi-captcha.service.js";

/**
 * The KiwiCaptcha widget as a standalone Angular component (Ivy, zone
 * safe, OnPush). Inputs cover the four-setting quickstart (endpoint,
 * sitekey, scope, lang) and the core's remaining options; outputs map
 * the driver's kiwi:* lifecycle events back inside the Angular zone.
 *
 * Driver work runs outside the zone; every output emission re-enters it,
 * so OnPush components see the change without extra wiring.
 */
@Component({
  selector: "kiwi-captcha",
  standalone: true,
  template: `<div #host class="kiwi-angular-host"></div>`,
  styles: [`:host { display: block; }`],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class KiwiCaptcha implements AfterViewInit {
  /** The four-setting quickstart plus the core's remaining options. */
  readonly endpoint = input<string | undefined>(undefined);
  readonly sitekey = input<string | undefined>(undefined);
  readonly scope = input<string | undefined>(undefined);
  readonly lang = input<string | undefined>(undefined);
  readonly theme = input<"light" | "dark" | "auto" | undefined>(undefined);
  readonly action = input<string | undefined>(undefined);
  readonly cData = input<string | undefined>(undefined);
  readonly chainTicket = input<string | undefined>(undefined);
  readonly requestBinding = input<string | undefined>(undefined);
  readonly fetchTimeoutMs = input<number | undefined>(undefined);
  readonly algorithm = input<string | undefined>(undefined);
  readonly execution = input<"execute" | undefined>(undefined);
  readonly scriptSrc = input<string | undefined>(undefined);

  /** True once a widget generation is live in the host element. */
  readonly ready = signal(false);

  /** A solve produced a token. */
  readonly verified = output<KiwiVerifiedDetail>();
  /** Terminal failure after the driver's bounded retries. */
  readonly failed = output<string>();
  /** A verified token aged out. */
  readonly expired = output<void>();
  /** The driver registered the widget. */
  readonly widgetReady = output<string>();
  /** A transient failure entered the retry backoff. */
  readonly retrying = output<KiwiRetryDetail>();
  /** The off-main-thread solver could not start. */
  readonly workerUnavailable = output<string>();
  /** An execution-armed challenge could not run its program. */
  readonly executionUnavailable = output<string>();

  private readonly hostRef = viewChild.required<ElementRef<HTMLElement>>("host");
  private readonly zone = inject(NgZone);
  private readonly destroyRef = inject(DestroyRef);
  private readonly service = inject(KiwiCaptchaService);

  private handle: KiwiWidgetHandle | null = null;
  private destroyed = false;

  ngAfterViewInit(): void {
    const container = this.hostRef().nativeElement;
    this.destroyRef.onDestroy(() => {
      this.destroyed = true;
      this.handle?.destroy();
      this.handle = null;
      this.ready.set(false);
    });
    this.zone.runOutsideAngular(() => {
      void this.service
        .render(container, this.readOptions())
        .then((handle) => {
          if (this.destroyed) {
            // The view died while the driver was loading: discard.
            handle.destroy();
            return;
          }
          this.handle = handle;
          this.zone.run(() => this.ready.set(true));
        })
        .catch((err: unknown) => {
          this.zone.run(() => this.failed.emit(String(err)));
        });
    });
  }

  /** The verified token, or "" while unverified or expired. */
  getResponse(): string {
    return this.handle?.getResponse() ?? "";
  }

  /** Whether the last verified token has expired. */
  isExpired(): boolean {
    return this.handle?.isExpired() ?? false;
  }

  /** Cancel the current run and acquire a fresh challenge. */
  reset(): void {
    this.handle?.reset();
  }

  /** Start or await the solve; resolves the token. */
  execute(): Promise<string> {
    return this.handle
      ? this.handle.execute()
      : Promise.reject(new Error("kiwicaptcha: widget not mounted"));
  }

  private readOptions(): KiwiRenderOptions & KiwiLoadOptions {
    return {
      endpoint: this.endpoint(),
      sitekey: this.sitekey(),
      scope: this.scope(),
      lang: this.lang(),
      theme: this.theme(),
      action: this.action(),
      cData: this.cData(),
      chainTicket: this.chainTicket(),
      requestBinding: this.requestBinding(),
      fetchTimeoutMs: this.fetchTimeoutMs(),
      algorithm: this.algorithm(),
      execution: this.execution(),
      scriptSrc: this.scriptSrc(),
      onReady: (scope) => this.zone.run(() => this.widgetReady.emit(scope)),
      onVerifying: () => undefined,
      onVerify: (token, detail) => this.zone.run(() => this.verified.emit(detail)),
      onError: (message) => this.zone.run(() => this.failed.emit(message)),
      onExpire: () => this.zone.run(() => this.expired.emit()),
      onRetry: (detail) => this.zone.run(() => this.retrying.emit(detail)),
      onWorkerUnavailable: (reason) =>
        this.zone.run(() => this.workerUnavailable.emit(reason)),
      onExecutionUnavailable: (reason) =>
        this.zone.run(() => this.executionUnavailable.emit(reason)),
    };
  }
}
