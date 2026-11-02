package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/aiops"
	"forest/go-api/internal/background"
	"forest/go-api/internal/config"
	"forest/go-api/internal/guest"
	httpapi "forest/go-api/internal/http"
	"forest/go-api/internal/nodeapi"
	"forest/go-api/internal/passport"
	"forest/go-api/internal/payment"
	"forest/go-api/internal/platform/ipgeo"
	"forest/go-api/internal/platform/postgres"
	"forest/go-api/internal/queue"
	"forest/go-api/internal/session"
	"forest/go-api/internal/subscribeguard"
	"forest/go-api/internal/telegram"
	usersvc "forest/go-api/internal/user"
)

func main() {
	cfg := config.Load()
	if err := config.ValidateProbeTrustedProxyCIDRs(cfg.ProbeTrustedProxyCIDRs); err != nil {
		log.Printf("invalid probe proxy configuration; forwarded probe addresses will not be trusted: %v", err)
		cfg.ProbeTrustedProxyCIDRs = []string{}
	}
	runtimeConfig := config.NewRuntimeState(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := postgres.Open(ctx, cfg.PostgresDSN)
	if err != nil {
		log.Fatalf("open postgres: %v", err)
	}
	if db != nil {
		defer func() {
			_ = db.Close()
		}()
	}

	if db != nil {
		geoSchemaCtx, geoSchemaCancel := context.WithTimeout(ctx, 5*time.Second)
		if err := postgres.EnsureOnlineLocationSchema(geoSchemaCtx, db); err != nil {
			log.Printf("online location schema initialization deferred; node reporting remains available: %v", err)
		}
		geoSchemaCancel()
	}
	geoDir := os.Getenv("FOREST_IPGEO_DIR")
	if geoDir == "" {
		geoDir = filepath.Join(cfg.PublicDir, "..", "storage", "ipgeo")
	}
	onlineGeo := ipgeo.New(geoDir)
	defer onlineGeo.Close()
	if status := onlineGeo.Status(); status.Status != "ready" {
		log.Printf("online geography database: %s; run scripts/prepare-ipgeo.sh to prepare IPv4/IPv6 data", status.Status)
	}
	var passportService passport.Service
	var sessionService session.Service
	var userService usersvc.Service
	var paymentService payment.Service
	var aiTelegram *aiops.TelegramBridge
	var aiOpsService *aiops.Service
	var adminService admin.Service
	var nodeService nodeapi.Service
	var telegramService *telegram.Service
	var backgroundRunner *background.Runner
	guardOptions := []httpapi.Option{}
	if db != nil {
		guard := subscribeguard.NewStore(db, cfg.AppKey)
		guardCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		guardErr := guard.Ensure(guardCtx)
		cancel()
		if guardErr != nil {
			log.Print("subscribe guard initialization failed; subscriptions remain available")
		} else {
			guardOptions = append(guardOptions, httpapi.WithSubscribeGuard(guard))
			go guard.Run(ctx)
		}
	}
	authCache := session.NewAuthCache(session.DefaultAuthCacheTTL)
	jobQueue := queue.NewRuntime(cfg.QueueWorkers, 0)
	jobQueue.Start()
	defer jobQueue.Shutdown(context.Background())
	if db != nil {
		userDBService := usersvc.NewDBService(cfg, db).WithRuntimeConfig(runtimeConfig).WithQueueRuntime(jobQueue).WithAuthCache(authCache)
		telegramService = telegram.NewService(cfg, db).WithRuntimeConfig(runtimeConfig).WithQueueRuntime(jobQueue)
		userDBService = userDBService.WithAdminNotifier(telegramService)
		passportService = passport.NewDBServiceWithConfig(cfg, db).WithRuntimeConfig(runtimeConfig).WithQueueRuntime(jobQueue).WithAuthCache(authCache)
		sessionService = session.NewDBService(cfg, db).WithAuthCache(authCache)
		userService = userDBService
		paymentService = payment.NewDBService(cfg, db, userDBService).WithRuntimeConfig(runtimeConfig)
		adminDBService := admin.NewDBService(cfg, db, userDBService).WithRuntimeConfig(runtimeConfig).WithQueueRuntime(jobQueue).WithAuthCache(authCache).WithOnlineGeoResolver(onlineGeo)
		if err := initializeDNSFailoverBeforeServe(ctx, adminDBService); err != nil {
			log.Printf("DNS failover initialization deferred; subscriptions remain available: %v", err)
		}
		monitorInitCtx, monitorInitCancel := context.WithTimeout(ctx, 5*time.Second)
		if err := adminDBService.InitializeDispatchMonitorSchema(monitorInitCtx); err != nil {
			log.Printf("auxiliary monitor initialization deferred; legacy DNS remains available: %v", err)
		}
		monitorInitCancel()
		adminDBService.WithDNSFailoverEvaluationRequester(adminDBService).WithDNSFailoverNotifier(telegramService.DirectNotifier())
		startDNSFailoverAutomationAfterSchema(ctx, adminDBService)
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
			defer cancel()
			if err := stopDNSFailoverAutomationBeforeDependencies(shutdownCtx, adminDBService); err != nil {
				log.Printf("stop DNS failover automation: %v", err)
			}
		}()
		telegramService = telegramService.WithUserResolver(userDBService.ResolveClientUserID).WithAdminService(adminDBService)
		aiOpsService = aiops.NewService(cfg, db, adminDBService)
		defer aiOpsService.Close()
		aiTelegram = aiops.NewTelegramBridge(aiOpsService)
		telegramService.WithAIOps(aiTelegram)
		adminService = adminDBService
		nodeDBService := nodeapi.NewDBService(cfg, db, userDBService).WithRuntimeConfig(runtimeConfig).WithOnlineGeoResolver(onlineGeo)
		nodeService = nodeDBService
		adminDBService.WithOnlineLocationRefresh(nodeDBService.ReconcileOnlineLocations)
		backgroundRunner = background.NewRunner(jobQueue, adminDBService, userDBService, adminDBService, adminDBService)
	}

	server := &http.Server{
		Addr: cfg.Addr,
		Handler: httpapi.NewRouter(cfg, append(guardOptions,
			httpapi.WithRuntimeConfig(runtimeConfig),
			httpapi.WithReadyCheck(dbReadyCheck(db)),
			httpapi.WithGuestService(guest.NewDBService(cfg, db).WithRuntimeConfig(runtimeConfig)),
			httpapi.WithPassportService(passportService),
			httpapi.WithSessionService(sessionService),
			httpapi.WithUserService(userService),
			httpapi.WithPaymentService(paymentService),
			httpapi.WithAdminService(adminService),
			httpapi.WithAIOps(aiOpsService),
			httpapi.WithAIOpsTelegram(aiTelegram),
			httpapi.WithNodeService(nodeService),
			httpapi.WithQueueRuntime(jobQueue),
			httpapi.WithTelegramService(telegramService),
		)...),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	if aiTelegram != nil {
		if err := aiTelegram.Start(ctx, telegramService.AITransport()); err != nil {
			log.Printf("AI Telegram start: %v", err)
		}
		defer aiTelegram.Close()
	}
	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("server shutdown error: %v", err)
		}
	}()

	if backgroundRunner != nil {
		backgroundRunner.Start(ctx)
	}

	log.Printf("go api listening on %s", cfg.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen and serve: %v", err)
	}
}

type dnsFailoverSchemaInitializer interface {
	InitializeDNSFailoverSchema(context.Context) error
}

type dnsFailoverAutomationStarter interface {
	StartDNSFailoverAutomation(context.Context)
}

type dnsFailoverAutomationStopper interface {
	StopDNSFailoverAutomation(context.Context) error
}

func initializeDNSFailoverBeforeServe(ctx context.Context, initializer dnsFailoverSchemaInitializer) error {
	if initializer == nil {
		return nil
	}
	initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return initializer.InitializeDNSFailoverSchema(initCtx)
}

func startDNSFailoverAutomationAfterSchema(ctx context.Context, starter dnsFailoverAutomationStarter) {
	if starter != nil {
		starter.StartDNSFailoverAutomation(ctx)
	}
}

func stopDNSFailoverAutomationBeforeDependencies(ctx context.Context, stopper dnsFailoverAutomationStopper) error {
	if stopper == nil {
		return nil
	}
	return stopper.StopDNSFailoverAutomation(ctx)
}

func dbReadyCheck(db *sql.DB) func(context.Context) error {
	return func(ctx context.Context) error {
		if db == nil {
			return nil
		}
		return db.PingContext(ctx)
	}
}
