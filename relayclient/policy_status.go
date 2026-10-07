package relayclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// ReportPolicyStatus acknowledges the policy revision applied by the proxy
// sidecar. It uses the same sandbox bearer and guest TLS identity as Run.
func ReportPolicyStatus(ctx context.Context, cfg Config, revision uint32, loadError string) error {
	if revision == 0 {
		return fmt.Errorf("relayclient: policy revision is required")
	}
	target, secure, err := grpcTarget(firstNonEmpty(cfg.GatewayGRPCEndpoint, cfg.GatewayURL))
	if err != nil {
		return err
	}
	transport := credentials.TransportCredentials(insecure.NewCredentials())
	if secure {
		tlsConfig := cfg.TLSConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		transport = credentials.NewTLS(tlsConfig.Clone())
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(transport))
	if err != nil {
		return fmt.Errorf("relayclient: policy status connection failed: %w", err)
	}
	defer conn.Close()
	callCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+cfg.Token)
	statusValue := openshellv1.PolicyStatus_POLICY_STATUS_LOADED
	if strings.TrimSpace(loadError) != "" {
		statusValue = openshellv1.PolicyStatus_POLICY_STATUS_FAILED
	}
	_, err = openshellv1.NewOpenShellClient(conn).ReportPolicyStatus(callCtx, &openshellv1.ReportPolicyStatusRequest{
		SandboxId: cfg.Sandbox,
		Version:   revision,
		Status:    statusValue,
		LoadError: loadError,
	})
	return err
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
