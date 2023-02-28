package helper

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

type MyFormatter struct{}

var levelList = []string{
	"PANIC",
	"FATAL",
	"ERROR",
	"WARN",
	"INFO",
	"DEBUG",
	"TRACE",
}

var Logger *logrus.Logger

func (mf *MyFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var b *bytes.Buffer
	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}

	level := levelList[int(entry.Level)]
	strList := strings.Split(entry.Caller.File, "/")
	fileName := strList[len(strList)-1]
	b.WriteString(fmt.Sprintf("%s - [%s - %s:%d] - %s\n", level,
		entry.Time.Format("15:04:05,678"), fileName,
		entry.Caller.Line, entry.Message))
	return b.Bytes(), nil
}

func MakeLogger(filename string, log_level string) { //*logrus.Logger {
	display := false
	if filename != "" {
		display = true
	}
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		panic(err.Error())
	}
	f.Truncate(0)
	f.Seek(0, 0)
	//Logger := logrus.New()
	if display {
		logrus.SetOutput(io.MultiWriter(os.Stdout, f))
	} else {
		logrus.SetOutput(io.MultiWriter(f))
	}
	logrus.SetReportCaller(true)
	//logger set level?
	logrus.SetFormatter(&MyFormatter{})
	lvl, _ := logrus.ParseLevel(log_level)
	logrus.SetLevel(lvl)
	// logrus.Formatter = &logrus.TextFormatter{
	// 	ForceColors: true,
	// }
	// var originalMode uint32
	// stdout := windows.Handle(os.Stdout.Fd())
	// windows.GetConsoleMode(stdout, &originalMode)
	// windows.SetConsoleMode(stdout, originalMode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	// defer windows.SetConsoleMode(stdout, originalMode)
	//logrus.SetOutput(colorable.NewColorableStdout())
	//logrus.SetOutput(ansicolor.NewAnsiColorWriter(os.Stdout))
	logrus.Debugln("Logger initialized.")
}

func PrintByteArray(bytes []byte) string {
	var str strings.Builder
	for _, b := range bytes {
		if b >= 32 && b <= 126 {
			str.WriteByte(b)
		} else {
			str.WriteString(fmt.Sprintf("\\x%02x", b))
		}
	}
	return str.String()
}
