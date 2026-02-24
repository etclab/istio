package kcclient

import (
	"context"
	"io"

	"istio.io/istio/pkg/log"
	pb "istio.io/istio/security/pkg/key-curator/key-curator"
)

// RegistrationHandler is a callback invoked for each RegistrationNotification.
type RegistrationHandler func(notif *pb.RegistrationNotification)

// StreamRegistrations opens a server-streaming RPC to the KeyCurator and invokes
// handler for each RegistrationNotification received. subscriberId is the caller's
// own RBE user ID, used by the server to track what has already been sent and avoid
// duplicates on reconnect. If handler is nil, the notification is only logged.
// It blocks until the stream ends or the context is cancelled.
func (c *KCClient) StreamRegistrations(ctx context.Context, subscriberId int64,
	registerRequest *pb.RegisterRequest, handler RegistrationHandler) error {
	stream, err := c.client.StreamRegistrations(ctx, &pb.StreamRegistrationsRequest{
		SubscriberId:    subscriberId,
		RegisterRequest: registerRequest,
	})
	if err != nil {
		return err
	}

	for {
		notif, err := stream.Recv()
		if err == io.EOF {
			log.Infof("[dev] StreamRegistrations: stream closed by server")
			return nil
		}
		if err != nil {
			return err
		}
		log.Infof("[dev] StreamRegistrations: received registration for id=%d", notif.GetId())
		if handler != nil {
			handler(notif)
		}
	}
}
