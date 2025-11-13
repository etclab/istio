package etcdutil

import (
	"context"
	"fmt"
	"math"
	"time"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe"
	"github.com/etclab/rbe/proto"
	clientv3 "go.etcd.io/etcd/client/v3"
	gproto "google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/log"
	kconstants "istio.io/istio/security/pkg/key-curator/constants"
	pb "istio.io/istio/security/pkg/key-curator/key-curator"
)

func TryConnectToEtcd() (*clientv3.Client, error) {
	etcdClient, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"etcd.istio-system.svc:2379"},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("[dev] failed to create etcd client: %w", err)
	}

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = etcdClient.Status(ctx, etcdClient.Endpoints()[0])
	if err != nil {
		etcdClient.Close()
		return nil, fmt.Errorf("[dev] etcd server unreachable: %w", err)
	}

	log.Infof("[dev] Connected to etcd: %v", etcdClient.Endpoints())
	return etcdClient, nil
}

func TryConnectToEtcdWithRetry() (*clientv3.Client, error) {
	backoff := 5 * time.Second
	maxBackoff := 2 * time.Minute
	maxAttempts := 20
	attempts := 0

	for {
		attempts++
		client, err := TryConnectToEtcd()
		if err == nil {
			log.Infof("[dev] Successfully connected to etcd after %d attempts", attempts)
			return client, nil
		}

		log.Warnf("[dev] Failed to connect to etcd (attempt %d): %v", attempts, err)

		if maxAttempts > 0 && attempts >= maxAttempts {
			log.Errorf("[dev] Max connection attempts reached. Giving up on etcd connection")
			return nil, err
		}

		// Sleep with exponential backoff, capped at maxBackoff
		time.Sleep(backoff)
		backoff = time.Duration(math.Min(float64(backoff*2), float64(maxBackoff)))
	}
}

func SavePublicParamsToEtcd(etcdClient *clientv3.Client, pp *rbe.PublicParams,
	onlyCommitments bool) error {

	// if onlyCommitments is true, only save the commitments part
	// if false, save all parts
	// as the rest of the public params don't change
	saveAll := !onlyCommitments

	if saveAll {
		// rest of the public params
		maxUsers := pp.MaxUsers
		blockSize := pp.BlockSize
		numBlocks := pp.NumBlocks

		g1 := pp.G1
		g2 := pp.G2

		ppCopy := new(rbe.PublicParams)
		ppCopy.MaxUsers = maxUsers
		ppCopy.BlockSize = blockSize
		ppCopy.NumBlocks = numBlocks
		ppCopy.G1 = g1
		ppCopy.G2 = g2

		ppCopy.CRS = new(rbe.CRS)
		ppCopy.CRS.H1 = make([]*bls.G1, 0)
		ppCopy.CRS.H2 = make([]*bls.G2, 0)

		ppCopy.Commitments = make([]*bls.G1, 0)

		ppCopyValue := ppCopy.ToProto()
		ppValue, err := gproto.Marshal(ppCopyValue)
		if err != nil {
			return fmt.Errorf("[dev] failed to marshal public params: %v", err)
		}

		// this only saves maxUsers, blockSize, numBlocks, G1, G2
		err = PutKVToEtcd(etcdClient, kconstants.RBE_PP_KEY, ppValue)
		if err != nil {
			return err
		} else {
			log.Infof("[dev] saved public params metadata to etcd")
		}

		// crs has the largest size, so split it into H1 and H2 parts
		// and save it separately
		crsH1 := pp.CRS.H1
		crsH2 := pp.CRS.H2
		// save H1
		crsH1Proto := &pb.H1{}
		for _, v := range crsH1 {
			if v == nil {
				crsH1Proto.H1 = append(crsH1Proto.H1, &proto.G1{Point: []byte{}})
			} else {
				crsH1Proto.H1 = append(crsH1Proto.H1, &proto.G1{Point: v.BytesCompressed()})
			}
		}
		crsH1Bytes, err := gproto.Marshal(crsH1Proto)
		if err != nil {
			return fmt.Errorf("[dev] failed to marshal crsH1: %v", err)
		}
		err = PutKVToEtcd(etcdClient, kconstants.RBE_PP_CRS_H1_KEY, crsH1Bytes)
		if err != nil {
			return err
		} else {
			log.Infof("[dev] saved crsH1 to etcd")
		}

		// save H2
		crsH2Proto := &pb.H2{}
		for _, v := range crsH2 {
			if v == nil {
				crsH2Proto.H2 = append(crsH2Proto.H2, &proto.G2{Point: []byte{}})
			} else {
				crsH2Proto.H2 = append(crsH2Proto.H2, &proto.G2{Point: v.BytesCompressed()})
			}
		}
		crsH2Bytes, err := gproto.Marshal(crsH2Proto)
		if err != nil {
			return fmt.Errorf("[dev] failed to marshal crsH2: %v", err)
		}
		err = PutKVToEtcd(etcdClient, kconstants.RBE_PP_CRS_H2_KEY, crsH2Bytes)
		if err != nil {
			return err
		} else {
			log.Infof("[dev] saved crsH2 to etcd")
		}

	}

	// now save the commitments
	commitments := &pb.Commitments{}
	for _, v := range pp.Commitments {
		commitG1 := &proto.G1{Point: v.BytesCompressed()}
		commitments.Commitments = append(commitments.Commitments, commitG1)
	}
	commitmentsBytes, err := gproto.Marshal(commitments)
	if err != nil {
		return fmt.Errorf("[dev] failed to marshal public params commitments: %v", err)
	}

	err = PutKVToEtcd(etcdClient, kconstants.RBE_PP_COMMITMENTS_KEY, commitmentsBytes)
	if err != nil {
		return err
	} else {
		log.Infof("[dev] saved public params commitments to etcd")
	}

	return nil
}

func PutKVToEtcd(etcdClient *clientv3.Client, key string, value []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// TODO: lock/txn to prevent race conditions when updating commitments?
	_, err := etcdClient.Put(ctx, key, string(value))
	if err != nil {
		return fmt.Errorf("[dev] failed to store public params in etcd: %v", err)
	}

	log.Infof("[dev] stored key: %s in etcd", key)
	return nil
}

func SaveUserOpeningsToEtcd(etcdClient *clientv3.Client, registeredIds map[int]bool,
	openings [][]*bls.G1) error {

	for key, value := range registeredIds {
		if !value {
			log.Warnf("[dev] user id %d is not registered, skipping saving its opening", key)
		} else {
			log.Infof("[dev] user id %d is registered, saving its opening", key)

			id := key
			opening := []*proto.G1{}
			for _, v := range openings[id] {
				opening = append(opening, &proto.G1{Point: v.Bytes()})
			}

			openingBytes, err := gproto.Marshal(&pb.Opening{Opening: opening})
			if err != nil {
				return fmt.Errorf("[dev] failed to marshal opening: %v", err)
			}
			err = PutKVToEtcd(etcdClient, fmt.Sprintf("%s/%d", kconstants.RBE_OPENINGS_KEY, id), openingBytes)
			if err != nil {
				return err
			} else {
				log.Infof("[dev] stored opening for user id %d in etcd", id)
			}
		}
	}

	log.Infof("[dev] stored all registered user openings in etcd")
	return nil
}
