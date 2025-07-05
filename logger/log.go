package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
)

type Sloggers struct {
	slogs []*slog.Logger
	key   string
}

func (s *Sloggers) Log(ctx context.Context, level slog.Level, format string, args ...any) {
	for _, v := range s.slogs {
		v.Log(ctx, level, s.key, "message", fmt.Sprintf(format, args...))
	}
}

func (s *Sloggers) Debug(format string, args ...any) {
	for _, v := range s.slogs {
		v.Debug(s.key, "message", fmt.Sprintf(format, args...))
	}
}

func (s *Sloggers) Warn(format string, args ...any) {
	for _, v := range s.slogs {
		v.Warn(s.key, "message", fmt.Sprintf(format, args...))
	}
}

func (s *Sloggers) Info(format string, args ...any) {
	for _, v := range s.slogs {
		v.Info(s.key, "message", fmt.Sprintf(format, args...))
	}
}

func (s *Sloggers) Error(format string, args ...any) {
	for _, v := range s.slogs {
		v.Error(s.key, "message", fmt.Sprintf(format, args...))
	}
}

var found = map[string]*Sloggers{}
var writers = []io.Writer{}
var level slog.Level

func LogLevel(l slog.Level) {
	level = l
}

func LogNewOutput(w io.Writer) {
	writers = append(writers, w)
}

func Log(key string) *Sloggers {
	if s, ok := found[key]; ok {
		return s
	}

	s := &Sloggers{
		key: key,
	}

	for _, v := range writers {
		writer := slog.New(slog.NewJSONHandler(v, &slog.HandlerOptions{
			Level:     level,
			AddSource: true,
		}))
		s.slogs = append(s.slogs, writer)
	}

	found[key] = s

	return s
}

func DebugWrite(key string, i int, err error, data []byte) {
	Log(key).Debug("wrote data length %d error: %s | data: %s", i, err, string(data))
}

func DebugRead(key string, i int, err error, data []byte) {
	Log(key).Debug("read data length %d data: %s", len(data), string(data))
}
