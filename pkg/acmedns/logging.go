package acmedns

import (
	"go.uber.org/zap/zapcore"

	"go.uber.org/zap"
)

func SetupLogging(config AcmeDnsConfig) (*zap.Logger, error) {
	var (
		logger     *zap.Logger
		zapCfg     zap.Config
		err        error
		outLogPath []string
		errLogPath []string
	)

	logformat := "console"
	if config.Logconfig.Format == "json" {
		logformat = "json"
	}

	if config.Logconfig.Logtype == "stdout" || config.Logconfig.Logtype == "both" {
		outLogPath = append(outLogPath, "stdout")
		errLogPath = append(errLogPath, "stderr")
	}
	// I wanted to be able to specify a different file path in ErrorOutputPaths,
	// but it seems that only internal Zap errors are output here.
	if config.Logconfig.Logtype == "file" || config.Logconfig.Logtype == "both" {
		if config.Logconfig.File != "" {
			outLogPath = append(outLogPath, config.Logconfig.File)
			errLogPath = append(errLogPath, config.Logconfig.File)
		}
	}

	zapCfg.Level, err = zap.ParseAtomicLevel(config.Logconfig.Level)
	if err != nil {
		return logger, err
	}
	zapCfg.Encoding = logformat
	zapCfg.OutputPaths = outLogPath
	zapCfg.ErrorOutputPaths = errLogPath
	zapCfg.EncoderConfig = zapcore.EncoderConfig{
		TimeKey:     "time",
		MessageKey:  "msg",
		LevelKey:    "level",
		EncodeLevel: zapcore.LowercaseLevelEncoder,
		EncodeTime:  zapcore.ISO8601TimeEncoder,
	}

	logger, err = zapCfg.Build()
	return logger, err
}
