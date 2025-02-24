package utils

import (
	"context"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func ExtractRequestMetadata(ctx context.Context) (userAgent, clientIP string) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ""
	}

	if ips := md.Get("x-client-ip"); len(ips) > 0 && ips[0] != "" {
		clientIP = ips[0]
	}

	if uas := md.Get("x-user-agent"); len(uas) > 0 && uas[0] != "" {
		userAgent = uas[0]
	}

	if userAgent == "" {
		if uas := md.Get("user-agent"); len(uas) > 0 && uas[0] != "" {
			userAgent = uas[0]
		}
	}

	if clientIP == "" {
		p, ok := peer.FromContext(ctx)
		if ok {
			clientIP = p.Addr.String()
		}
	}

	return userAgent, clientIP
}
