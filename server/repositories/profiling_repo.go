package repositories

import (
	"os"
	"runtime/pprof"

	"go.uber.org/zap"
)

/*
Endpoint : /debug/pprof for profilling data over server
go tool pprof -pdf profile_cpu.prof > profile_cpu.pdf
*/

// ProfilingService represents a WebService that can start/stop a CPU profile and write results to a file
type ProfilingService struct {
	Cpuprofile string   // the output filename to write profile results, e.g. myservice.prof
	Cpufile    *os.File // if not nil, then profiling is active
	CpuLogger  *zap.Logger
}

// NewProfileService creates a new profile
func NewProfileService(outputFilename string, logger *zap.Logger) *ProfilingService {
	return &ProfilingService{
		Cpuprofile: outputFilename,
		CpuLogger:  logger,
	}
}

// StartProfiling starts pprof profile
func (p *ProfilingService) StartProfiling() {
	cpufile, err := os.Create(p.Cpuprofile)
	if err != nil {
		p.CpuLogger.Fatal("could not create file", zap.Error(err))
		return
	}

	p.Cpufile = cpufile
	pprof.StartCPUProfile(cpufile)
}

// StopProfiling stops pprof and closes cpu file
func (p *ProfilingService) StopProfiling() {
	pprof.StopCPUProfile()
	p.Cpufile.Close()
	p.Cpufile = nil
}
