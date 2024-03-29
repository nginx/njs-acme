export enum LogLevel {
  /**
   * Debug is a synthetic log level to control log verbosity.
   *
   * ngx.INFO is the lowest level that njs supports, but often there are logs
   * only useful during the development process.
   */
  Debug = 1,
  Info,
  Warn,
  Error,
}

/** what Logger needs from the global ngx */
type NgxLog = Pick<NgxObject, 'INFO' | 'WARN' | 'ERR' | 'log'>

/**
 * Logger is a leveled logger on top of ngx.log that adds a consistent
 * prefix to log messages.
 *
 * @example
 * const log = new Logger('my module')
 * log.info('foo')
 * // equivalent to `ngx.log(ngx.INFO, 'njs-acme: [my module] foo')`
 *
 * log.debug('bar') // does nothing by default
 * log.minLevel = LogLevel.Debug // enabling more verbosity
 *
 * log.debug('bar')
 * // now equivalent to `ngx.log(ngx.INFO, 'njs-acme: [my module] bar')`
 *
 * // multiple args are stringified and joined on space:
 * log.info('baz:', true, {key: "value"})
 * // equivalent to `ngx.log(ngx.INFO, 'njs-acme: [my module] baz: true {"key":"value"}')`
 */
export class Logger {
  private prefix: string
  private readonly logLevelMap: Record<LogLevel, number>
  private readonly ngx: NgxLog

  /**
   * @param module preprended to every log message, if non-empty
   * @param minLevel lowest level to log, anything below will be ignored
   * @param ngx log sink, intended for testing purposes
   */
  constructor(
    module = '',
    public minLevel: LogLevel = LogLevel.Info,
    base?: NgxLog
  ) {
    // the global `ngx` object is late bound, and undefined if we use it as a
    // default parameter
    this.ngx = base ?? ngx
    this.prefix = module ? `njs-acme: [${module}]` : 'njs-acme:'
    this.logLevelMap = {
      [LogLevel.Debug]: this.ngx.INFO,
      [LogLevel.Info]: this.ngx.INFO,
      [LogLevel.Warn]: this.ngx.WARN,
      [LogLevel.Error]: this.ngx.ERR,
    }
  }

  private log(level: LogLevel, args: unknown[]) {
    if (args.length === 0) {
      return
    }
    if (level < this.minLevel) {
      return
    }

    const message = [this.prefix, ...args]
      .map((a) => (typeof a === 'string' ? a : JSON.stringify(a)))
      .join(' ')

    this.ngx.log(this.logLevelMap[level], message)
  }

  /**
   * debug is a synthetic log level to control verbosity, use this for logs that
   * are useful only during the development process.
   *
   * Will appear in logs as ngx.INFO.
   * */
  debug(...args: unknown[]): void {
    this.log(LogLevel.Debug, args)
  }
  info(...args: unknown[]): void {
    this.log(LogLevel.Info, args)
  }
  warn(...args: unknown[]): void {
    this.log(LogLevel.Warn, args)
  }
  error(...args: unknown[]): void {
    this.log(LogLevel.Error, args)
  }
}
