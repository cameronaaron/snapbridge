package connector

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/0xzer/snapper"
	"github.com/cameronaaron/snapchat-bridge/bridge"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type SnapchatConnector struct {
	br     *bridge.Bridge
	client *snapper.Client
}

func (sc *SnapchatConnector) Init(bridge *bridge.Bridge) {
	sc.br = bridge
	session, err := snapper.NewSessionFromCookies("YOUR_COOKIE_STRING")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create Snapchat session")
	}
	sc.client = snapper.NewClient(session, zerolog.Logger{}, nil)
}

func (sc *SnapchatConnector) Start(ctx context.Context) error {
	log.Info().Msg("Snapchat Connector Started")
	return nil
}

func (sc *SnapchatConnector) GetCapabilities() *bridge.NetworkGeneralCapabilities {
	return &bridge.NetworkGeneralCapabilities{}
}

func (sc *SnapchatConnector) GetName() bridge.BridgeName {
	return bridge.BridgeName{
		DisplayName:      "Snapchat",
		NetworkURL:       "https://snapchat.com",
		NetworkID:        "snapchat",
		BeeperBridgeType: "github.com/cameronaaron/snapchat-bridge",
		DefaultPort:      29323,
	}
}

func (sc *SnapchatConnector) HandleMatrixMessage(ctx context.Context, msg *bridge.MatrixMessage) (*bridge.MatrixMessageResponse, error) {
	messageBuilder := sc.client.NewCreateMessageBuilder().
		AddConversationDestination(msg.Portal.ID).
		SetTextMessage(msg.Content.Body).
		SetSavePolicy(snapper.ContentEnvelope_SavePolicy_LIFETIME)

	sent, err := sc.client.Messaging.SendContentMessage(messageBuilder)
	if err != nil {
		log.Error().Err(err).Msg("Failed to send message to Snapchat")
		return nil, err
	}

	return &bridge.MatrixMessageResponse{
		DB: &bridge.Message{
			ID:       sent.MessageID,
			SenderID: sent.SenderID,
		},
	}, nil
}

func (sc *SnapchatConnector) ReceiveMessage(w http.ResponseWriter, r *http.Request) {
	var incomingMessage snapper.Message
	err := json.NewDecoder(r.Body).Decode(&incomingMessage)
	if err != nil {
		log.Error().Err(err).Msg("Invalid request body")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	matrixMessage := bridge.MatrixMessage{
		Portal: bridge.Portal{
			ID: incomingMessage.ConversationID,
		},
		Content: bridge.MessageContent{
			Body: incomingMessage.Body,
		},
	}

	err = sc.br.SendMessage(&matrixMessage)
	if err != nil {
		log.Error().Err(err).Msg("Failed to send message to Matrix")
		http.Error(w, "Failed to send message to Matrix", http.StatusInternalServerError)
	}
}
