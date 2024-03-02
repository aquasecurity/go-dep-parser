package log

import (
	"go.uber.org/zap"
)

var Logger = NewLazyLogger(func() (*zap.SugaredLogger, error) {
	config := zap.Config{
		Level:            zap.NewAtomicLevelAt(zap.InfoLevel),
		Development:      false,
		Encoding:         "console",
		EncoderConfig:    zap.NewDevelopmentEncoderConfig(),
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}
	logger, err := config.Build()
	if err != nil {
		return nil, err
	}
	return logger.Sugar(), nil
})

func SetLogger(l *zap.SugaredLogger) {
	Logger.zapLogger = l
}
