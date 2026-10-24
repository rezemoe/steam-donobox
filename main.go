package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	maFilePath := flag.String("mafile", "", "path to the account's .maFile (required)")
	interval := flag.Duration("interval", time.Minute, "how often to check for new trade offers")
	flag.Parse()

	if *maFilePath == "" {
		log.Fatal("-mafile is required")
	}
	password := os.Getenv("STEAM_PASSWORD")
	if password == "" {
		log.Fatal("STEAM_PASSWORD environment variable is required")
	}
	mf, err := loadMaFile(*maFilePath)
	if err != nil {
		log.Fatalf("load maFile: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bot := &bot{mf: mf, password: password}
	if err := bot.login(ctx); err != nil {
		log.Fatalf("login: %v", err)
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		bot.check(ctx)
		select {
		case <-ctx.Done():
			log.Print("shutting down")
			return
		case <-ticker.C:
		}
	}
}

type bot struct {
	mf       *MaFile
	password string
	session  *Session
}

func (b *bot) login(ctx context.Context) error {
	s, err := Login(ctx, b.mf, b.password)
	if err != nil {
		return err
	}
	b.session = s
	log.Printf("logged in as %s (%s), session valid until %s", b.mf.AccountName, s.SteamID, s.ExpiresAt.Format(time.RFC3339))
	return nil
}

func (b *bot) ensureSession(ctx context.Context) error {
	if b.session != nil && (b.session.ExpiresAt.IsZero() || time.Until(b.session.ExpiresAt) > 10*time.Minute) {
		return nil
	}
	log.Print("session expired or about to expire, logging in again")
	return b.login(ctx)
}

func (b *bot) check(ctx context.Context) {
	if err := b.ensureSession(ctx); err != nil {
		log.Printf("login failed: %v", err)
		return
	}

	offers, err := b.session.GetIncomingOffers(ctx)
	if isAuthError(err) {
		log.Printf("session rejected (%v), logging in again", err)
		b.session = nil
		if err = b.ensureSession(ctx); err == nil {
			offers, err = b.session.GetIncomingOffers(ctx)
		}
	}
	if err != nil {
		log.Printf("fetch trade offers: %v", err)
		return
	}

	for i := range offers {
		o := &offers[i]
		if o.State != tradeOfferStateActive {
			continue
		}
		if !o.IsGift() {
			log.Printf("skipping offer %s from %s: gives %d item(s), receives %d", o.ID, o.PartnerSteamID(), len(o.ItemsToGive), len(o.ItemsToReceive))
			continue
		}
		if err := b.session.AcceptOffer(ctx, o); err != nil {
			log.Printf("accept offer %s from %s: %v", o.ID, o.PartnerSteamID(), err)
			continue
		}
		log.Printf("accepted offer %s from %s: received %d item(s)", o.ID, o.PartnerSteamID(), len(o.ItemsToReceive))
	}
}
