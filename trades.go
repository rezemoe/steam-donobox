package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	tradeOfferStateActive = 2
	steamID64Base         = 76561197960265728
)

type TradeOffer struct {
	ID             string `json:"tradeofferid"`
	AccountIDOther uint64 `json:"accountid_other"`
	Message        string `json:"message"`
	State          int    `json:"trade_offer_state"`
	IsOurOffer     bool   `json:"is_our_offer"`
	ItemsToGive    []struct {
		AppID   int    `json:"appid"`
		AssetID string `json:"assetid"`
	} `json:"items_to_give"`
	ItemsToReceive []struct {
		AppID   int    `json:"appid"`
		AssetID string `json:"assetid"`
	} `json:"items_to_receive"`
}

func (o *TradeOffer) IsGift() bool {
	return !o.IsOurOffer &&
		o.State == tradeOfferStateActive &&
		len(o.ItemsToGive) == 0 &&
		len(o.ItemsToReceive) > 0
}

func (o *TradeOffer) PartnerSteamID() string {
	return strconv.FormatUint(o.AccountIDOther+steamID64Base, 10)
}

func (s *Session) GetIncomingOffers(ctx context.Context) ([]TradeOffer, error) {
	var r struct {
		Received []TradeOffer `json:"trade_offers_received"`
	}
	err := apiCall(ctx, s.client, http.MethodGet, "IEconService", "GetTradeOffers", url.Values{
		"access_token":        {s.AccessToken},
		"get_received_offers": {"1"},
		"active_only":         {"1"},
		"get_descriptions":    {"0"},
	}, &r)
	if err != nil {
		return nil, err
	}
	return r.Received, nil
}

func (s *Session) AcceptOffer(ctx context.Context, o *TradeOffer) error {
	form := url.Values{
		"sessionid":    {s.SessionID},
		"serverid":     {"1"},
		"tradeofferid": {o.ID},
		"partner":      {o.PartnerSteamID()},
		"captcha":      {""},
	}
	u := fmt.Sprintf("%s/tradeoffer/%s/accept", communityBase, o.ID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Origin", communityBase)
	req.Header.Set("Referer", fmt.Sprintf("%s/tradeoffer/%s/", communityBase, o.ID))

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	var r struct {
		TradeID                 string `json:"tradeid"`
		StrError                string `json:"strError"`
		NeedsMobileConfirmation bool   `json:"needs_mobile_confirmation"`
		NeedsEmailConfirmation  bool   `json:"needs_email_confirmation"`
	}
	_ = json.Unmarshal(data, &r)
	if r.StrError != "" {
		return fmt.Errorf("steam: %s", r.StrError)
	}
	if resp.StatusCode != http.StatusOK {
		return &httpError{Status: resp.StatusCode, Body: truncate(string(data), 200)}
	}
	if r.NeedsMobileConfirmation || r.NeedsEmailConfirmation {
		return fmt.Errorf("offer unexpectedly requires confirmation")
	}
	return nil
}
