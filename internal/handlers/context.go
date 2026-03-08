package handlers

import (
	"context"

	"github.com/Andrew55529/sso_Server/internal/tokens"
)

func contextWithClaims(ctx context.Context, c *tokens.Claims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}

func claimsFromContext(ctx context.Context) *tokens.Claims {
	c, _ := ctx.Value(claimsKey).(*tokens.Claims)
	return c
}
