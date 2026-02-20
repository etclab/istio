package kcclient

import (
	"context"
	"io"

	"google.golang.org/protobuf/types/known/emptypb"
	"istio.io/istio/pkg/log"
)

// StreamRegistrations opens a server-streaming RPC to the KeyCurator and logs
// each RegistrationNotification received. It blocks until the stream ends or
// the context is cancelled.
func (c *KCClient) StreamRegistrations(ctx context.Context) error {
	stream, err := c.client.StreamRegistrations(ctx, &emptypb.Empty{})
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
		log.Infof("[dev] StreamRegistrations: %s (id=%d)", notif.GetMessage(), notif.GetId())
	}
}
