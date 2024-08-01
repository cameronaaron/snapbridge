package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/0xzer/snapper"
	"github.com/0xzer/snapper/crypto"
	"github.com/0xzer/snapper/debug"
	"github.com/0xzer/snapper/protos"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"go.mau.fi/util/ptr"
	"go.mau.fi/util/configupgrade"
)

// Information to find out exactly which commit the bridge was built from.
// These are filled at build time with the -X linker flag.
var (
	Tag       = "unknown"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	m := bridgev2.BridgeMain{
		Name:        "snapchat-bridge",
		Description: "A Matrix-Snapchat bridge",
		URL:         "https://github.com/cameronaaron/snapchat-bridge",
		Version:     "1.0.0",
		Connector:   &SnapchatConnector{},
	}
	m.InitVersion(Tag, Commit, BuildTime)
	m.Run()
}

type SnapchatConnector struct {
	br     *bridgev2.Bridge
	client *snapper.Client
}

var _ bridgev2.NetworkConnector = (*SnapchatConnector)(nil)

func (sc *SnapchatConnector) Init(bridge *bridgev2.Bridge) {
	sc.br = bridge
}

func (sc *SnapchatConnector) Start(ctx context.Context) error {
	log.Info().Msg("Snapchat Connector Started")
	server, ok := sc.br.Matrix.(bridgev2.MatrixConnectorWithServer)
	if !ok {
		return fmt.Errorf("matrix connector does not implement MatrixConnectorWithServer")
	} else if server.GetPublicAddress() == "" {
		return fmt.Errorf("public address of bridge not configured")
	}
	r := server.GetRouter().PathPrefix("/_snapchat").Subrouter()
	r.HandleFunc("/{loginID}/receive", sc.ReceiveMessage).Methods(http.MethodPost)
	return nil
}

func (sc *SnapchatConnector) ReceiveMessage(w http.ResponseWriter, r *http.Request) {
	// Validate the signature of the incoming request
	if !sc.validateSignature(r) {
		http.Error(w, "Invalid signature", http.StatusForbidden)
		return
	}

	// Parse the incoming request body
	var snapMessage ParsedSnapchatMessage
	err := json.NewDecoder(r.Body).Decode(&snapMessage)
	if err != nil {
		log.Error().Err(err).Msg("Invalid request body")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Fetch additional message data using snapper client
	messageData, err := sc.client.Messaging.QueryMessages(snapMessage.ConversationID, 1, 0)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query messages")
		http.Error(w, "Failed to query messages", http.StatusInternalServerError)
		return
	}

	// Process the message data and send it to the Matrix server
	matrixMessage := bridgev2.MatrixMessage{
		Portal: bridgev2.Portal{
			ID: makePortalID(snapMessage.ConversationID),
		},
		Content: bridgev2.MessageContent{
			Body: snapMessage.Body,
		},
	}

	err = sc.br.SendMessage(&matrixMessage)
	if err != nil {
		log.Error().Err(err).Msg("Failed to send message to Matrix")
		http.Error(w, "Failed to send message to Matrix", http.StatusInternalServerError)
	}

	// Send a blank response to Snapchat
	w.WriteHeader(http.StatusOK)
}

// validateSignature validates the incoming request signature
func (sc *SnapchatConnector) validateSignature(r *http.Request) bool {
	// I need to implement signature validation logic
	return true 
}

func (sc *SnapchatConnector) GetCapabilities() *bridgev2.NetworkGeneralCapabilities {
	return &bridgev2.NetworkGeneralCapabilities{}
}

func (sc *SnapchatConnector) GetName() bridgev2.BridgeName {
	return bridgev2.BridgeName{
		DisplayName:      "Snapchat",
		NetworkURL:       "https://snapchat.com",
		NetworkIcon:      "mxc://maunium.net/FYuKJHaCrSeSpvBJfHwgYylP",
		NetworkID:        "snapchat",
		BeeperBridgeType: "github.com/your_username/snapchat-bridge",
		DefaultPort:      29324,
	}
}

func (sc *SnapchatConnector) GetConfig() (example string, data any, upgrader configupgrade.Upgrader) {
	return "", nil, configupgrade.NoopUpgrader
}

func (sc *SnapchatConnector) GetDBMetaTypes() database.MetaTypes {
	return database.MetaTypes{
		Portal:   nil,
		Ghost:    nil,
		Message:  nil,
		Reaction: nil,
		UserLogin: func() any {
			return &UserLoginMetadata{}
		},
	}
}

type UserLoginMetadata struct {
	Cookies     string `json:"cookies"`
	FideliusKey string `json:"fidelius_key"`
}

func (sc *SnapchatConnector) LoadUserLogin(ctx context.Context, login *bridgev2.UserLogin) error {
	meta := login.Metadata.(*UserLoginMetadata)

	// Initialize snapper client from cookies
	session, err := snapper.NewSessionFromCookies(meta.Cookies)
	if err != nil {
		return fmt.Errorf("failed to create Snapchat session from cookies: %w", err)
	}

	// Initialize Fidelius keys
	fideliusKeys, err := crypto.LoadPublicKeyFromBase64(meta.FideliusKey)
	if err != nil {
		return fmt.Errorf("failed to load Fidelius keys from base64: %w", err)
	}

	// Create snapper client
	client := snapper.NewClient(session, debug.NewLogger(), nil)
	client.Session.FideliusKeys = fideliusKeys // Assign Fidelius keys to the session

	login.Client = &SnapchatClient{
		UserLogin: login,
		Client:    client,
	}
	return nil
}

type SnapchatClient struct {
	UserLogin *bridgev2.UserLogin
	Client    *snapper.Client
}

var _ bridgev2.NetworkAPI = (*SnapchatClient)(nil)
var _ bridgev2.IdentifierResolvingNetworkAPI = (*SnapchatClient)(nil)

func (sc *SnapchatClient) Connect(ctx context.Context) error {
	// nil
	return nil
}

func (sc *SnapchatClient) Disconnect() {}

func (sc *SnapchatClient) IsLoggedIn() bool {
	return true
}

func (sc *SnapchatClient) LogoutRemote(ctx context.Context) {}

func (sc *SnapchatClient) GetCapabilities(ctx context.Context, portal *bridgev2.Portal) *bridgev2.NetworkRoomCapabilities {
	return &bridgev2.NetworkRoomCapabilities{
		MaxTextLength: 1600,
	}
}

func makeUserID(snapchatUsername string) networkid.UserID {
	return networkid.UserID(snapchatUsername)
}

func makePortalID(conversationID string) networkid.PortalID {
	return networkid.PortalID(conversationID)
}

func makeUserLoginID(cookies string, fideliusKey string) networkid.UserLoginID {
	return networkid.UserLoginID(fmt.Sprintf("%s:%s", cookies, fideliusKey))
}

func (sc *SnapchatClient) IsThisUser(ctx context.Context, userID networkid.UserID) bool {
	return networkid.UserID(sc.UserLogin.ID) == userID
}

func (sc *SnapchatClient) GetChatInfo(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.ChatInfo, error) {
	return &bridgev2.ChatInfo{
		Members: &bridgev2.ChatMemberList{
			IsFull: true,
			Members: []bridgev2.ChatMember{
				{
					EventSender: bridgev2.EventSender{
						IsFromMe: true,
						Sender:   makeUserID(sc.UserLogin.Metadata.(*UserLoginMetadata).Cookies),
					},
					Membership: event.MembershipJoin,
					PowerLevel: ptr.Ptr(50),
				},
				{
					EventSender: bridgev2.EventSender{
						Sender: networkid.UserID(portal.ID),
					},
					Membership: event.MembershipJoin,
					PowerLevel: ptr.Ptr(50),
				},
			},
		},
	}, nil
}

func (sc *SnapchatClient) GetUserInfo(ctx context.Context, ghost *bridgev2.Ghost) (*bridgev2.UserInfo, error) {
	return &bridgev2.UserInfo{
		Identifiers: []string{fmt.Sprintf("snapchat:%s", ghost.ID)},
		Name:        ptr.Ptr(ghost.ID),
	}, nil
}

func (sc *SnapchatClient) GetWebhookURL() string {
	server := sc.UserLogin.Bridge.Matrix.(bridgev2.MatrixConnectorWithServer)
	return fmt.Sprintf("%s/_snapchat/%s/receive", server.GetPublicAddress(), sc.UserLogin.ID)
}

func (sc *SnapchatClient) HandleWebhook(ctx context.Context, params map[string]string) {
	parsedMessage, err := parseSnapchatMessage(params)
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse Snapchat message")
		return
	}

	sc.UserLogin.Bridge.QueueRemoteEvent(sc.UserLogin, &simplevent.Message[map[string]string]{
		EventMeta: simplevent.EventMeta{
			Type: bridgev2.RemoteEventMessage,
			LogContext: func(c zerolog.Context) zerolog.Context {
				return c.
					Str("from", parsedMessage.Sender).
					Str("message_id", parsedMessage.MessageID)
			},
			PortalKey: networkid.PortalKey{
				ID:       makePortalID(parsedMessage.ConversationID),
				Receiver: sc.UserLogin.ID,
			},
			CreatePortal: true,
			Sender: bridgev2.EventSender{
				Sender: makeUserID(parsedMessage.Sender),
			},
			Timestamp: parsedMessage.Timestamp,
		},
		Data:               params,
		ID:                 networkid.MessageID(parsedMessage.MessageID),
		ConvertMessageFunc: sc.convertMessage,
	})
}

type ParsedSnapchatMessage struct {
	Sender         string    `json:"sender"`
	ConversationID string    `json:"conversationId"`
	MessageID      string    `json:"messageId"`
	Timestamp      time.Time `json:"timestamp"`
	Body           string    `json:"body"`
}

func parseSnapchatMessage(params map[string]string) (*ParsedSnapchatMessage, error) {
	sender := params["From"]
	conversationID := params["ConversationID"]
	messageID := params["MessageID"]
	timestampStr := params["Timestamp"]
	body := params["Body"]

	timestamp, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	return &ParsedSnapchatMessage{
		Sender:         sender,
		ConversationID: conversationID,
		MessageID:      messageID,
		Timestamp:      timestamp,
		Body:           body,
	}, nil
}

func (sc *SnapchatClient) convertMessage(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, data map[string]string) (*bridgev2.ConvertedMessage, error) {
	return &bridgev2.ConvertedMessage{
		Parts: []*bridgev2.ConvertedMessagePart{{
			Type: event.EventMessage,
			Content: &event.MessageEventContent{
				MsgType: event.MsgText,
				Body:    data["Body"],
			},
		}},
	}, nil
}

func (sc *SnapchatClient) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) {
	snapMessage, err := sc.Client.Messaging.SendContentMessage(sc.Client.NewCreateMessageBuilder().
		AddConversationDestination(msg.Portal.ID).
		SetTextMessage(msg.Content.Body).
		SetSavePolicy(protos.ContentEnvelope_SavePolicy_LIFETIME))

	if err != nil {
		return nil, fmt.Errorf("failed to send message to Snapchat: %w", err)
	}

	return &bridgev2.MatrixMessageResponse{
		DB: &bridgev2.Message{
			ID:       networkid.MessageID(snapMessage.MessageID),
			SenderID: makeUserID(*msg.Content.Sender.Sender), // Using sender from Matrix message
		},
	}, nil
}

func (sc *SnapchatClient) ResolveIdentifier(ctx context.Context, identifier string, createChat bool) (*bridgev2.ResolveIdentifierResponse, error) {
	snapUser, err := sc.Client.Users.GetPublicInfo([]string{identifier})
	if err != nil {
		return nil, fmt.Errorf("failed to get public info for Snapchat user: %w", err)
	}

	userID := makeUserID(identifier)
	portalID := networkid.PortalKey{
		ID:       makePortalID(snapUser[0].ID),
		Receiver: sc.UserLogin.ID,
	}

	ghost, err := sc.UserLogin.Bridge.GetGhostByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get ghost: %w", err)
	}
	portal, err := sc.UserLogin.Bridge.GetPortalByKey(ctx, portalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get portal: %w", err)
	}
	ghostInfo, _ := sc.GetUserInfo(ctx, ghost)
	portalInfo, _ := sc.GetChatInfo(ctx, portal)
	return &bridgev2.ResolveIdentifierResponse{
		Ghost:    ghost,
		UserID:   userID,
		UserInfo: ghostInfo,
		Chat: &bridgev2.CreateChatResponse{
			Portal:     portal,
			PortalKey:  portalID,
			PortalInfo: portalInfo,
		},
	}, nil
}

func (sc *SnapchatConnector) GetLoginFlows() []bridgev2.LoginFlow {
	return []bridgev2.LoginFlow{{
		Name:        "Snapchat Cookies",
		Description: "Log in using your Snapchat cookies",
		ID:          "snapchat-cookies",
	}}
}

type SnapchatLogin struct {
	User        *bridgev2.User
	Cookies     string `json:"cookies"`
	FideliusKey string `json:"fidelius_key"`
}

var _ bridgev2.LoginProcessCookies = (*SnapchatLogin)(nil)

func (sc *SnapchatConnector) CreateLogin(ctx context.Context, user *bridgev2.User, flowID string) (bridgev2.LoginProcess, error) {
	if flowID != "snapchat-cookies" {
		return nil, fmt.Errorf("unknown login flow ID")
	}
	return &SnapchatLogin{User: user}, nil
}

func (sl *SnapchatLogin) Start(ctx context.Context) (*bridgev2.LoginStep, error) {
	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeCookies,
		StepID:       "fi.mau.snapchat.enter_cookies",
		Instructions: "Please visit web.snapchat.com and log in. After that, open the browser developer tools. In the 'Application' tab, find 'Storage', and click on 'Cookies'. Copy the cookies for the 'web.snapchat.com' domain. You should see 'sc-cookies-accepted', 'EssentialSession', 'Preferences', 'Performance', 'Marketing', '__Host-X-Snap-Client-Cookie', '__Host-sc-a-session', 'sc-a-nonce', '__Host-sc-a-nonce', 'sc-a-csrf', and 'blizzard_client_id' cookies. Paste those cookies into the bridge bot in the next step. \n\n Then, open the 'Storage' tab again, click on 'Local Storage', and copy the value for 'blizzard_client_id'. Paste that into the bridge bot in the next step.",
	}, nil
}

func (sl *SnapchatLogin) SubmitUserInput(ctx context.Context, input map[string]string) (*bridgev2.LoginStep, error) {
	return nil, fmt.Errorf("this login flow does not accept user input")
}

func (sl *SnapchatLogin) SubmitCookies(ctx context.Context, cookies string, localStorage map[string]string) (*bridgev2.LoginStep, error) {
	sl.Cookies = cookies
	sl.FideliusKey = localStorage["blizzard_client_id"]

	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeComplete,
		StepID:       "fi.mau.snapchat.complete",
		Instructions: "Successfully logged in",
		CompleteParams: &bridgev2.LoginCompleteParams{
			UserLoginID: makeUserLoginID(sl.Cookies, sl.FideliusKey),
			UserLogin:   sl.User.NewLogin(ctx, &database.UserLogin{
				ID:         makeUserLoginID(sl.Cookies, sl.FideliusKey),
				RemoteName: "Snapchat",
				Metadata: &UserLoginMetadata{
					Cookies:    sl.Cookies,
					FideliusKey: sl.FideliusKey,
				},
			}, nil),
		},
	}, nil
}

func (sl *SnapchatLogin) Cancel() {}
