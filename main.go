package main

import (
	"log"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	metricsPath         = "/metrics"          // 基础metrics
	cadvisorMetricsPath = "/metrics/cadvisor" // 容器和系统metrics
	resourceMetricsPath = "/metrics/resource" // 资源使用metrics
	proberMetricsPath   = "/metrics/probes"   // 探测器metrics
)

var (
	enablePprof = true
	port        = "58081"

	// HTTP 请求相关指标
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status", "long_running"},
	)

	httpInflightRequests = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "http_inflight_requests",
			Help: "Current number of HTTP requests being served",
		},
		[]string{"method", "endpoint", "long_running"},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"method", "endpoint", "long_running"},
	)

	// 资源使用相关指标
	cpuUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cpu_usage_seconds",
			Help: "CPU usage in seconds",
		},
		[]string{"type"},
	)

	memoryUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "memory_usage_bytes",
			Help: "Memory usage in bytes",
		},
		[]string{"type"},
	)

	// 探测器相关指标
	probeResults = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "probe_results",
			Help: "Results of health probes",
		},
		[]string{"probe_type"},
	)

	probeDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "probe_duration_seconds",
			Help:    "Duration of health probes in seconds",
			Buckets: []float64{.005, .01, .025, .05, .1},
		},
		[]string{"probe_type"},
	)
)

func init() {
	// 注册所有指标
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpInflightRequests)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(cpuUsage)
	prometheus.MustRegister(memoryUsage)
	prometheus.MustRegister(probeResults)
	prometheus.MustRegister(probeDuration)

	// 初始化一些示例指标
	cpuUsage.WithLabelValues("user").Set(0)
	cpuUsage.WithLabelValues("system").Set(0)
	memoryUsage.WithLabelValues("used").Set(0)
	memoryUsage.WithLabelValues("free").Set(0)
}

// PrometheusMiddleware 是一个 Gin 中间件，用于收集 HTTP 指标
func PrometheusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		method := c.Request.Method
		path := c.FullPath()
		if path == "" {
			path = "undefined"
		}

		// 判断是否为长连接请求
		longRunning := "false"
		if c.Request.Header.Get("Connection") == "keep-alive" {
			longRunning = "true"
		}

		// 记录正在处理的请求数
		httpInflightRequests.WithLabelValues(method, path, longRunning).Inc()
		defer httpInflightRequests.WithLabelValues(method, path, longRunning).Dec()

		// 处理请求
		c.Next()

		// 记录请求持续时间
		duration := time.Since(start).Seconds()
		httpRequestDuration.WithLabelValues(method, path, longRunning).Observe(duration)

		// 记录请求总数和状态码
		status := c.Writer.Status()
		httpRequestsTotal.WithLabelValues(method, path, string(rune(status)), longRunning).Inc()
	}
}

func registerPprof(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}

func main() {
	// 创建 HTTP 服务器
	mux := http.NewServeMux()

	// 注册基础 metrics 端点
	mux.Handle(metricsPath, promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}))

	// 注册 cadvisor metrics 端点
	cadvisorRegistry := prometheus.NewRegistry()
	cadvisorRegistry.MustRegister(cpuUsage)
	cadvisorRegistry.MustRegister(memoryUsage)
	mux.Handle(cadvisorMetricsPath, promhttp.HandlerFor(cadvisorRegistry, promhttp.HandlerOpts{}))

	// 注册资源 metrics 端点
	resourceRegistry := prometheus.NewRegistry()
	resourceRegistry.MustRegister(httpInflightRequests)
	resourceRegistry.MustRegister(httpRequestDuration)
	mux.Handle(resourceMetricsPath, promhttp.HandlerFor(resourceRegistry, promhttp.HandlerOpts{}))

	// 注册探测器 metrics 端点
	proberRegistry := prometheus.NewRegistry()
	proberRegistry.MustRegister(probeResults)
	proberRegistry.MustRegister(probeDuration)
	mux.Handle(proberMetricsPath, promhttp.HandlerFor(proberRegistry, promhttp.HandlerOpts{}))

	// 如果启用了 pprof，注册 pprof 端点
	if enablePprof {
		registerPprof(mux)
		log.Printf("Pprof endpoints enabled at /debug/pprof/")
	}

	// 创建 Gin 引擎
	r := gin.Default()

	// 使用 Prometheus 中间件
	r.Use(PrometheusMiddleware())

	// 将 Gin 的路由处理添加到 mux
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		r.ServeHTTP(w, req)
	})

	// 示例路由
	r.GET("/hello", func(c *gin.Context) {
		// 模拟随机延迟
		time.Sleep(time.Duration(100+time.Now().UnixNano()%400) * time.Millisecond)
		c.JSON(200, gin.H{
			"message": "Hello, World!",
		})
	})

	// 健康检查端点
	r.GET("/healthz", func(c *gin.Context) {
		start := time.Now()
		// 模拟健康检查
		time.Sleep(50 * time.Millisecond)
		duration := time.Since(start).Seconds()
		probeDuration.WithLabelValues("healthz").Observe(duration)
		probeResults.WithLabelValues("healthz").Set(1)
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	// 启动服务器
	addr := ":" + port
	log.Printf("Server starting on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
