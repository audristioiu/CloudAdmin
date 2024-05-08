package helpers

import (
	"bytes"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
)

func TestParseFQLFilter(t *testing.T) {
	filter := `description=NULL&&is_running="false"||kname="test"&&created_timestamp<"1day"`
	var buf bytes.Buffer
	logger := zaptest.NewLogger(t, zaptest.WrapOptions(zap.Hooks(func(entry zapcore.Entry) error {
		buf.WriteString(entry.Message)
		buf.WriteByte('\n')
		return nil
	})))

	fqlFilter, err := ParseFQLFilter(filter, logger)
	if err != nil {
		t.Fatalf("error in parsing filter : %s", err.Error())
	}
	fqlFilterCount := 0
	for _, pair := range fqlFilter {
		if len(pair) > 0 {
			fqlFilterCount++
		}
	}
	if fqlFilterCount != 7 {
		t.Fatalf("failed to parse filter . Invalid filter resulted : %v", fqlFilter)
	}
}

func TestInvalidParseFQLFilter(t *testing.T) {
	filter := `(description="NULL" && is_running="false)||(kname="test" && description="NULL")`
	var buf bytes.Buffer
	logger := zaptest.NewLogger(t, zaptest.WrapOptions(zap.Hooks(func(entry zapcore.Entry) error {
		buf.WriteString(entry.Message)
		buf.WriteByte('\n')
		return nil
	})))

	_, err := ParseFQLFilter(filter, logger)
	if err == nil {
		t.Fatal("error in parsing filter , invalid quoted text")
	}
	filter = `description="NULL"`
	_, err = ParseFQLFilter(filter, logger)
	if err == nil {
		t.Fatal("error in parsing filter : found NULL in text token")
	}
}
