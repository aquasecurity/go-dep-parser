package log

import "go.uber.org/zap"

type lazyLogger struct {
	zapFactory func() (*zap.SugaredLogger, error)
	zapLogger  *zap.SugaredLogger
}

// NewLazyLogger creates a new lazy logger with the specified function to call to create zap logger
func NewLazyLogger(zapFactory func() (*zap.SugaredLogger, error)) lazyLogger {
	return lazyLogger{zapFactory: zapFactory}
}

// ZapLogger creates a new zap logger if no logger was created yet
func (l *lazyLogger) ZapLogger() *zap.SugaredLogger {
	if l.zapLogger == nil {
		l.zapLogger, _ = l.zapFactory() // no:lint: errcheck
	}
	return l.zapLogger
}

// Debug uses fmt.Sprint to construct and log a message.
func (l *lazyLogger) Debug(args ...interface{}) {
	l.ZapLogger().Debug(args...)
}

// Debugf uses fmt.Sprintf to log a templated message.
func (l *lazyLogger) Debugf(template string, args ...interface{}) {
	l.ZapLogger().Debugf(template, args...)
}

// Debugw logs a message with some additional context. The variadic key-value
// pairs are treated as they are in With.
//
// When debug-level logging is disabled, this is much faster than
//
//	s.With(keysAndValues).Debug(msg)
func (l *lazyLogger) Debugw(msg string, keysAndValues ...interface{}) {
	l.ZapLogger().Debugw(msg, keysAndValues...)
}

// Info uses fmt.Sprint to log a templated message.
func (l *lazyLogger) Info(args ...interface{}) {
	l.ZapLogger().Info(args...)
}

// Infof uses fmt.Sprintf to log a templated message.
func (l *lazyLogger) Infof(template string, args ...interface{}) {
	l.ZapLogger().Infof(template, args...)
}

// Infow logs a message with some additional context. The variadic key-value
// pairs are treated as they are in With.
func (l *lazyLogger) Infow(msg string, keysAndValues ...interface{}) {
	l.ZapLogger().Infow(msg, keysAndValues...)
}

// Warn uses fmt.Sprint to log a templated message.
func (l *lazyLogger) Warn(args ...interface{}) {
	l.ZapLogger().Warn(args...)
}

// Warnf uses fmt.Sprintf to log a templated message.
func (l *lazyLogger) Warnf(template string, args ...interface{}) {
	l.ZapLogger().Warnf(template, args...)
}

// Warnw logs a message with some additional context. The variadic key-value
// pairs are treated as they are in With.
func (l *lazyLogger) Warnw(msg string, keysAndValues ...interface{}) {
	l.ZapLogger().Warnw(msg, keysAndValues...)
}

// Error uses fmt.Sprint to log a templated message.
func (l *lazyLogger) Error(args ...interface{}) {
	l.ZapLogger().Error(args...)
}

// Errorf uses fmt.Sprintf to log a templated message.
func (l *lazyLogger) Errorf(template string, args ...interface{}) {
	l.ZapLogger().Errorf(template, args...)
}

// Errorw logs a message with some additional context. The variadic key-value
// pairs are treated as they are in With.
func (l *lazyLogger) Errorw(msg string, keysAndValues ...interface{}) {
	l.ZapLogger().Errorw(msg, keysAndValues...)
}

// Fatal uses fmt.Sprint to construct and log a message, then calls os.Exit.
func (l *lazyLogger) Fatal(args ...interface{}) {
	l.ZapLogger().Fatal(args...)
}

// Fatalf uses fmt.Sprintf to log a templated message, then calls os.Exit.
func (l *lazyLogger) Fatalf(template string, args ...interface{}) {
	l.ZapLogger().Fatalf(template, args...)
}
