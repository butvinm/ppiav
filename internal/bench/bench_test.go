package bench

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMeasure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		fn      func() error
		wantErr error
	}{
		{
			name: "success",
			fn:   func() error { return nil },
		},
		{
			name:    "error propagation",
			fn:      func() error { return errors.New("boom") },
			wantErr: errors.New("boom"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Measure("stage", tt.fn)
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr.Error(), err.Error())
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, "stage", s.Name)
		})
	}
}

func TestMeasureWallPositive(t *testing.T) {
	t.Parallel()

	s, err := Measure("sleep", func() error {
		time.Sleep(time.Millisecond)
		return nil
	})
	require.NoError(t, err)
	assert.Greater(t, s.Wall, time.Duration(0))
}

func TestMeasureWithSize(t *testing.T) {
	t.Parallel()

	s, err := MeasureWithSize("artifact", func() (uint64, error) {
		return 4242, nil
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(4242), s.Bytes)
}

func TestRepeat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		n        int
		fn       func() error
		wantLen  int
		wantErr  bool
		wantIter []int
	}{
		{
			name:     "success",
			n:        3,
			fn:       func() error { return nil },
			wantLen:  3,
			wantIter: []int{0, 1, 2},
		},
		{
			name: "error at second iter",
			n:    5,
			fn: func() func() error {
				calls := 0
				return func() error {
					calls++
					if calls == 2 {
						return errors.New("fail")
					}
					return nil
				}
			}(),
			wantLen:  2,
			wantErr:  true,
			wantIter: []int{0, 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			samples, err := Repeat(tt.n, "stage", tt.fn)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Len(t, samples, tt.wantLen)
			for i, want := range tt.wantIter {
				assert.Equal(t, want, samples[i].Iter)
				assert.Equal(t, "stage", samples[i].Name)
			}
		})
	}
}

func TestRepeatWithWarmup(t *testing.T) {
	t.Parallel()

	t.Run("warmup excluded from samples", func(t *testing.T) {
		var calls int
		samples, err := RepeatWithWarmup(3, 2, "stage", func() error {
			calls++
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 5, calls, "warmup runs should execute")
		require.Len(t, samples, 3)
		for i, s := range samples {
			assert.Equal(t, i, s.Iter, "Iter restarts at 0 after warmup")
		}
	})

	t.Run("error during warmup propagates", func(t *testing.T) {
		_, err := RepeatWithWarmup(3, 1, "stage", func() error {
			return errors.New("warmup boom")
		})
		require.Error(t, err)
	})
}

func TestRunWriteJSONRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "phase1", "run.json")

	run := NewRun("e2e", "phase1")
	run.Metadata["log_n"] = 14
	samples, err := Repeat(2, "stage", func() error { return nil })
	require.NoError(t, err)
	run.Append(samples...)

	require.NoError(t, run.WriteJSON(path))

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var got Run
	require.NoError(t, json.Unmarshal(data, &got))

	assert.Equal(t, run.Name, got.Name)
	assert.Equal(t, run.Phase, got.Phase)
	assert.Equal(t, runtime.Version(), got.GoVersion)
	assert.Equal(t, runtime.GOOS, got.GOOS)
	assert.Equal(t, runtime.GOARCH, got.GOARCH)
	assert.Equal(t, runtime.NumCPU(), got.NumCPU)
	require.Len(t, got.Samples, 2)
	assert.Equal(t, "stage", got.Samples[0].Name)
	assert.EqualValues(t, 14, got.Metadata["log_n"])
}

func TestRunWriteJSONAtomic(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	run := NewRun("e2e", "phase1")
	require.NoError(t, run.WriteJSON(path))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), ".tmp-", "no leftover tmp file")
	}
}

func TestVmHWM(t *testing.T) {
	t.Parallel()

	v := readVmHWM()
	if runtime.GOOS == "linux" {
		// VmHWM should be readable and non-zero on a running test process.
		assert.Greater(t, v, uint64(0))
	} else {
		assert.Equal(t, uint64(0), v)
	}
}
