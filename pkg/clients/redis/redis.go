// pkg/clients/redis/redis.go
package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/FurmanovVitaliy/auth-grpc-service/utils"
	"github.com/go-redis/redis/v8"
)

var ErrKeyNotFound = errors.New("key not found")

type RedisClient interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Keys(ctx context.Context, pattern string) ([]string, error)
	Get(ctx context.Context, key string) (string, error)
	Del(ctx context.Context, keys ...string) error
	Ping(ctx context.Context) error
	TTL(ctx context.Context, key string) (time.Duration, error)
	Close() error
}

type redisClient struct {
	client *redis.Client
}

func (r *redisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

func (r *redisClient) Get(ctx context.Context, key string) (string, error) {
	result, err := r.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrKeyNotFound
	}
	return result, err
}

func (r *redisClient) Del(ctx context.Context, keys ...string) error {
	return r.client.Del(ctx, keys...).Err()
}

func (r *redisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	return r.client.TTL(ctx, key).Result()
}

func (r *redisClient) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

func (r *redisClient) Keys(ctx context.Context, pattern string) ([]string, error) {
	return r.client.Keys(ctx, pattern).Result()
}

func (r *redisClient) Close() error {
	return r.client.Close()
}

func NewRedisClient(ctx context.Context, maxAttempts int, host, port, password string, db int) (RedisClient, string, error) {
	var client *redis.Client
	var err error

	addr := fmt.Sprintf("%s:%s", host, port)

	err = utils.DoWithRetry(func() error {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		client = redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: password,
			DB:       db,
		})

		return client.Ping(ctx).Err()
	}, maxAttempts, 5*time.Second)

	if err != nil {
		return nil, "", fmt.Errorf("failed to connect to Redis after %d attempts: %w", maxAttempts, err)
	}

	version, err := client.Info(ctx, "server").Result()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get Redis version: %w", err)
	}

	return &redisClient{client: client}, version, nil
}
